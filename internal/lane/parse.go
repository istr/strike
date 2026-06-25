package lane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/schema"

	"gopkg.in/yaml.v3"
)

// ParseDuration converts a lane duration pointer to clock.Duration.
// Returns defaultVal if d is nil.
func ParseDuration(d *Duration, defaultVal clock.Duration) (clock.Duration, error) {
	if d == nil {
		return defaultVal, nil
	}
	return clock.ParseDuration(string(*d))
}

// Parse reads a lane YAML file, validates it against the embedded CUE schema,
// and returns a typed Lane instance together with the raw sha256 digest of
// the file bytes. Hash and parse consume the same single read, so the digest
// is bound to exactly the bytes the Lane was built from; it is carried into
// the sealed attestation as lane_digest.
func Parse(fp FilePath) (*Lane, DigestRef, error) {
	raw, err := fp.Read()
	if err != nil {
		return nil, DigestRef{}, fmt.Errorf("read: %w", err)
	}
	// The input is "sha256:" followed by 64 lowercase hex by construction, so
	// it always satisfies #Digest and MustParseDigest's panic is unreachable.
	// Using the canonical constructor keeps digest validation in one place and
	// holds Parse at the cyclomatic-complexity ceiling.
	sum := sha256.Sum256(raw)
	dg := MustParseDigest("sha256:" + hex.EncodeToString(sum[:]))

	// YAML to generic map (for CUE validation)
	var asMap any
	if yamlErr := yaml.Unmarshal(raw, &asMap); yamlErr != nil {
		return nil, DigestRef{}, fmt.Errorf("yaml parse: %w", yamlErr)
	}

	// Convert to JSON (CUE is a superset of JSON)
	asJSON, err := json.Marshal(asMap)
	if err != nil {
		return nil, DigestRef{}, fmt.Errorf("json marshal: %w", err)
	}

	// Validate against embedded CUE schema
	if err := schema.ValidateLaneJSON(asJSON); err != nil {
		return nil, DigestRef{}, fmt.Errorf("validation:\n%w", err)
	}

	// Deserialize from JSON into typed Lane struct.
	// Using JSON (not YAML) because gengotypes only emits json struct tags.
	var p Lane
	if err := json.Unmarshal(asJSON, &p); err != nil {
		return nil, DigestRef{}, fmt.Errorf("deserialize: %w", err)
	}

	// Validate: exactly one of image, image_from, pack, or deploy per step
	for _, s := range p.Steps {
		count := 0
		if s.Image != nil {
			count++
		}
		if s.ImageFromStep != nil {
			count++
		}
		if s.Pack != nil {
			count++
		}
		if s.Deploy != nil {
			count++
		}
		if count != 1 {
			return nil, DigestRef{}, fmt.Errorf(
				"step %q: exactly one of image, imageFromStep, pack, or deploy required", s.ID)
		}
	}

	if err := validateDeployPresence(&p); err != nil {
		return nil, DigestRef{}, err
	}

	if err := validateResolver(&p); err != nil {
		return nil, DigestRef{}, err
	}

	if err := ValidatePaths(&p); err != nil {
		return nil, DigestRef{}, err
	}

	return &p, dg, nil
}

// ValidatePaths rejects unsafe paths in outputs and pack dests.
// Defense-in-depth -- os.Root enforces at runtime, but rejecting early
// produces better error messages.
//
// outputs[].path and pack.files[].dest are container-internal paths
// (e.g., /src/node_modules, /usr/bin/strike). They must be absolute
// and canonical (no ".." components).
func ValidatePaths(p *Lane) error {
	for _, s := range p.Steps {
		if err := validateStepPaths(s); err != nil {
			return err
		}
	}
	return nil
}

// validateStepPaths checks one step's output, pack-dest, and workdir paths.
func validateStepPaths(s Step) error {
	if len(s.Outputs) > 0 && s.Workdir == nil && s.Pack == nil {
		return fmt.Errorf("step %q: declares outputs but no workdir", s.ID)
	}
	if err := validateOutputPaths(s); err != nil {
		return err
	}
	if s.Pack != nil {
		for _, f := range s.Pack.Files {
			if err := f.Dest.Validate(); err != nil {
				return fmt.Errorf("step %q: pack dest %q: %w", s.ID, f.Dest, err)
			}
		}
	}
	if s.Workdir != nil {
		if err := s.Workdir.Validate(); err != nil {
			return fmt.Errorf("step %q: workdir %q: %w", s.ID, *s.Workdir, err)
		}
	}
	return nil
}

// validateOutputPaths validates the path of each file or directory output,
// when present.
func validateOutputPaths(s Step) error {
	for _, out := range s.Outputs {
		if out.Path != nil {
			if err := out.Path.Validate(); err != nil {
				return fmt.Errorf("step %q: output path %q: %w", s.ID, *out.Path, err)
			}
		}
	}
	return nil
}

// validateDeployPresence enforces ADR-039 D1: a lane must contain at
// least one deploy step. A lane that produces artifacts but deploys
// nowhere has no attestation to produce; publishing those artifacts
// (a registry push) is itself a deploy step.
func validateDeployPresence(p *Lane) error {
	for _, s := range p.Steps {
		if s.Deploy != nil {
			return nil
		}
	}
	return fmt.Errorf("lane %q: no deploy step; a lane must declare at least one deploy step", p.Name)
}

// validateResolver enforces the IP-literal constraint on the
// declared DoT resolver host. The resolver is itself the
// resolution authority for the lane; a host given as an FQDN
// would require external DNS to resolve, defeating the purpose.
//
// This is semantically a schema constraint -- it describes
// what a valid lane looks like -- but technically lives in Go.
// Encoding the IP literal forms (IPv4, IPv6, bracketed-IPv6,
// each optionally with port) as a CUE regex would be a 200-400-
// character maintenance liability with no net cross-implementation
// benefit: a Rust verifier would parse with std::net::IpAddr,
// not mirror our regex. The Go check using net/netip is the
// canonical enforcement; the schema records the intent in a
// doc comment.
//
// Defense-in-depth, analogous to ValidatePaths: this runs at
// parse time (early), so `strike validate` and `strike run`
// fail identically on the same invalid input.
func validateResolver(p *Lane) error {
	host := string(p.Resolver.Host)
	if host == "" {
		return fmt.Errorf("resolver: host required")
	}
	// ParseAddrPort handles `1.1.1.1:853` and `[2606:4700::1111]:853`.
	// If port absent, fall back to ParseAddr for `1.1.1.1` and
	// `2606:4700::1111`.
	if _, err := netip.ParseAddrPort(host); err != nil {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf(
				"resolver host %q must be IP literal (IPv4 or IPv6, "+
					"with optional :port; bracketed form for v6+port); "+
					"FQDNs are not allowed because the resolver is itself "+
					"the resolution authority and cannot resolve its own "+
					"hostname",
				host)
		}
	}
	return nil
}
