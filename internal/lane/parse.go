package lane

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/istr/strike/internal/clock"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
	"github.com/istr/strike/specs"
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

var schema = buildSchema()

func buildSchema() string {
	// transport.cue shares package lane; strip the duplicate package
	// declaration so the two files can be compiled as one CUE source.
	var out []string
	for _, line := range strings.Split(specs.TransportSchema, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "package ") {
			continue
		}
		out = append(out, line)
	}
	return specs.LaneSchema + "\n" + strings.Join(out, "\n")
}

// Parse reads a lane YAML file, validates it against the embedded CUE schema,
// and returns a typed Lane instance.
func Parse(fp FilePath) (*Lane, error) {
	raw, err := fp.Read()
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// YAML to generic map (for CUE validation)
	var asMap any
	if yamlErr := yaml.Unmarshal(raw, &asMap); yamlErr != nil {
		return nil, fmt.Errorf("yaml parse: %w", yamlErr)
	}

	// Convert to JSON (CUE is a superset of JSON)
	asJSON, err := json.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}

	// Validate against embedded CUE schema
	if err := validate(asJSON); err != nil {
		return nil, fmt.Errorf("validation:\n%w", err)
	}

	// Deserialize from JSON into typed Lane struct.
	// Using JSON (not YAML) because gengotypes only emits json struct tags.
	var p Lane
	if err := json.Unmarshal(asJSON, &p); err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	// Validate: exactly one of image, image_from, pack, or deploy per step
	for _, s := range p.Steps {
		count := 0
		if s.Image != nil {
			count++
		}
		if s.ImageFrom != nil {
			count++
		}
		if s.Pack != nil {
			count++
		}
		if s.Deploy != nil {
			count++
		}
		if count != 1 {
			return nil, fmt.Errorf(
				"step %q: exactly one of image, image_from, pack, or deploy required", s.Name)
		}
	}

	if err := validateResolver(&p); err != nil {
		return nil, err
	}

	if err := ValidatePaths(&p); err != nil {
		return nil, err
	}

	return &p, nil
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
		return fmt.Errorf("step %q: declares outputs but no workdir", s.Name)
	}
	for _, out := range s.Outputs {
		if out.Path != nil {
			if err := out.Path.Validate(); err != nil {
				return fmt.Errorf("step %q: output path %q: %w", s.Name, *out.Path, err)
			}
		}
	}
	if s.Pack != nil {
		for _, f := range s.Pack.Files {
			if err := f.Dest.Validate(); err != nil {
				return fmt.Errorf("step %q: pack dest %q: %w", s.Name, f.Dest, err)
			}
		}
	}
	if s.Workdir != nil {
		if err := s.Workdir.Validate(); err != nil {
			return fmt.Errorf("step %q: workdir %q: %w", s.Name, *s.Workdir, err)
		}
	}
	return nil
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

func validate(data []byte) error {
	ctx := cuecontext.New()

	compiledSchema := ctx.CompileString(schema).
		LookupPath(cue.ParsePath("#Lane"))

	expr, err := cuejson.Extract("lane.yaml", data)
	if err != nil {
		return err
	}

	unified := compiledSchema.Unify(ctx.BuildExpr(expr))
	return FormatValidationError(unified.Validate(cue.Concrete(true)))
}
