package lane

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// ValidateLane is the lane-structure validation phase. It runs between Parse
// and Build over the parsed lane and its step index: the pure-lane validators
// and the reference-integrity checks that Build's resolve methods used to carry
// inline. Build assumes a lane that has passed this gate. The leaf-topology
// validators need the built graph and stay on the DAG.
func ValidateLane(p *Lane, index map[primitive.Identifier]*Step) error {
	if err := validateStepKindDisjointness(p); err != nil {
		return err
	}
	if err := validateDeployPresence(p); err != nil {
		return err
	}
	if err := validateResolver(p); err != nil {
		return err
	}
	if err := ValidatePaths(p); err != nil {
		return err
	}
	if err := validateOutputIDDisjointness(p); err != nil {
		return err
	}
	if err := validateImageFromRefs(p, index); err != nil {
		return err
	}
	if err := validateInputRefs(p, index); err != nil {
		return err
	}
	if err := validatePackFileRefs(p, index); err != nil {
		return err
	}
	if err := validateDeployArtifactRefs(p, index); err != nil {
		return err
	}
	if err := validateProvenancePaths(p); err != nil {
		return err
	}
	if err := validateMountDisjointness(p); err != nil {
		return err
	}
	if err := validatePeerAnchors(p); err != nil {
		return err
	}
	if err := validateBaseSBOMTrustAnchor(p); err != nil {
		return err
	}
	return nil
}

// validateImageFromRefs checks that each step's imageFromStep references a known
// step that declares an image output.
func validateImageFromRefs(p *Lane, index map[primitive.Identifier]*Step) error {
	for _, s := range p.Steps {
		if s.ImageFromStep == nil {
			continue
		}
		from := *s.ImageFromStep
		fromStep, ok := index[from]
		if !ok {
			return fmt.Errorf("step %q: imageFromStep references unknown step %q", s.ID, from)
		}
		if fromStep.Output == "" {
			return fmt.Errorf("step %q: imageFromStep %q declares no image output", s.ID, from)
		}
	}
	return nil
}

// validateInputRefs checks that each input references a known step and output,
// and that a subpath is not applied to a file output.
func validateInputRefs(p *Lane, index map[primitive.Identifier]*Step) error {
	for _, s := range p.Steps {
		for _, inp := range s.Inputs {
			fromStep, ok := index[inp.From.Step]
			if !ok {
				return fmt.Errorf("step %q: input at %q references unknown step %q",
					s.ID, inp.Mount, inp.From.Step)
			}
			out := findOutput(fromStep, inp.From.Output)
			if out == nil {
				return fmt.Errorf("step %q: input at %q: output %q not found in step %q",
					s.ID, inp.Mount, inp.From.Output, inp.From.Step)
			}
			if inp.Subpath != nil && out.Type == "file" {
				return fmt.Errorf("step %q: input at %q: subpath %q not allowed on file output %q.%q",
					s.ID, inp.Mount, *inp.Subpath, inp.From.Step, inp.From.Output)
			}
		}
	}
	return nil
}

// validatePackFileRefs checks that each pack file references a known step and
// output.
func validatePackFileRefs(p *Lane, index map[primitive.Identifier]*Step) error {
	for _, s := range p.Steps {
		if s.Pack == nil {
			continue
		}
		for _, f := range s.Pack.Files {
			fromStep, ok := index[f.From.Step]
			if !ok {
				return fmt.Errorf("step %q: pack file references unknown step %q", s.ID, f.From.Step)
			}
			if findOutput(fromStep, f.From.Output) == nil {
				return fmt.Errorf("step %q: pack file output %q not found in step %q",
					s.ID, f.From.Output, f.From.Step)
			}
		}
	}
	return nil
}

// validateDeployArtifactRefs checks that each deploy artifact source references
// a known step (and output, for an OutputRef source).
func validateDeployArtifactRefs(p *Lane, index map[primitive.Identifier]*Step) error {
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		for artName, artRef := range s.Deploy.Artifacts {
			if err := validateDeployArtifactRef(s.ID, artName, artRef.From, index); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateDeployArtifactRef validates one deploy.artifacts[name].from
// disjunction: a StepImageRef (the producing step's image, by step) or an
// OutputRef (a named file or directory output, by step+output).
func validateDeployArtifactRef(name primitive.Identifier, artName string, src ArtifactSource, index map[primitive.Identifier]*Step) error {
	switch ref := src.(type) {
	case StepImageRef:
		fromStep, ok := index[ref.Step]
		if !ok {
			return fmt.Errorf(
				"step %q: deploy artifact %q references unknown step %q", name, artName, ref.Step)
		}
		if fromStep.Output == "" {
			return fmt.Errorf(
				"step %q: deploy artifact %q: step %q declares no image output", name, artName, ref.Step)
		}
		return nil
	case OutputRef:
		fromStep, ok := index[ref.Step]
		if !ok {
			return fmt.Errorf(
				"step %q: deploy artifact %q references unknown step %q", name, artName, ref.Step)
		}
		if findOutput(fromStep, ref.Output) == nil {
			return fmt.Errorf(
				"step %q: deploy artifact %q: output %q not found in step %q",
				name, artName, ref.Output, ref.Step)
		}
		return nil
	default:
		return fmt.Errorf(
			"step %q: deploy artifact %q: unknown source kind %q", name, artName, src.SourceKind())
	}
}

// findOutput returns a pointer to the FileOutput with the given name,
// or nil if not found. The returned pointer aliases into s.Outputs,
// so callers must not mutate s afterwards.
func findOutput(s *Step, name primitive.Identifier) *FileOutput {
	for i := range s.Outputs {
		if s.Outputs[i].ID == name {
			return &s.Outputs[i]
		}
	}
	return nil
}

// validateOutputIDDisjointness rejects a step whose outputs declare the same
// id twice. The output id is the per-step addressing key for an output and its
// layer: a duplicate would alias output resolution (findOutput returns the
// first match) and overwrite the lane-state registration keyed by that id, so
// one output would silently vanish. Distinct ids may still share a path
// basename; only ids must be disjoint (ADR-046).
func validateOutputIDDisjointness(p *Lane) error {
	for _, s := range p.Steps {
		seen := make(map[primitive.Identifier]struct{}, len(s.Outputs))
		for _, out := range s.Outputs {
			if _, dup := seen[out.ID]; dup {
				return fmt.Errorf("step %q: duplicate output id %q", s.ID, out.ID)
			}
			seen[out.ID] = struct{}{}
		}
	}
	return nil
}

// validateProvenancePaths checks that each step's provenance.path
// (if declared) is relative, canonical, and lies within a declared output.
// A whole-workdir output (path absent) contains any provenance file.
func validateProvenancePaths(p *Lane) error {
	for _, s := range p.Steps {
		if s.Provenance == nil {
			continue
		}
		provPath := s.Provenance.Path
		if err := provPath.Validate(); err != nil {
			return fmt.Errorf("step %q: provenance.path %q: %w", s.ID, provPath, err)
		}
		found := false
		for _, out := range s.Outputs {
			if out.Path == nil { // whole workdir contains everything
				found = true
				break
			}
			prefix := string(*out.Path) + "/"
			if provPath == *out.Path || provPath.HasPrefix(prefix) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("step %q: provenance.path %q is not within any declared output",
				s.ID, provPath)
		}
	}
	return nil
}

// validateMountDisjointness checks that input mounts within the same step
// do not nest. Two mounts a and b conflict iff a == b, or a is a path
// prefix of b, or b is a path prefix of a. Workdir is not a mount and
// is excluded from this check.
//
// When a step legitimately needs multiple sources to appear at related
// container paths (e.g. /work + /work/node_modules), the user must compose
// them in a separate pack step that produces a single image output, then
// mount that image at the desired root. This keeps mount topology trivial.
func validateMountDisjointness(l *Lane) error {
	for _, s := range l.Steps {
		var mounts []primitive.AbsPath
		for in := range l.Inputs(s.ID) {
			mounts = append(mounts, in.Mount)
		}
		for i := range mounts {
			for j := i + 1; j < len(mounts); j++ {
				if mountsConflict(mounts[i], mounts[j]) {
					return fmt.Errorf(
						"step %q: input mounts %q and %q overlap; compose them in a pack step",
						s.ID, mounts[i], mounts[j])
				}
			}
		}
	}
	return nil
}

// mountsConflict reports whether two absolute container paths overlap
// in a way that would make their bind mounts nested.
func mountsConflict(a, b primitive.AbsPath) bool {
	ca := a.Clean()
	cb := b.Clean()
	if ca == cb {
		return true
	}
	return isPathPrefix(ca, cb) || isPathPrefix(cb, ca)
}

// isPathPrefix reports whether prefix is a strict path-component prefix
// of full. "/a" is a prefix of "/a/b" but not of "/abc".
func isPathPrefix(prefix, full string) bool {
	if !strings.HasPrefix(full, prefix) {
		return false
	}
	if len(full) == len(prefix) {
		return false // identical, not a strict prefix
	}
	// "/" is a prefix of everything -- the separator is already there.
	if prefix == "/" {
		return true
	}
	return full[len(prefix)] == '/'
}

// validatePeerAnchors enforces that no two steps declare the same network
// endpoint (host:port) with different trust anchors. Declaring one endpoint
// with the same anchor from several steps is allowed; declaring it with
// differing anchors is a contradiction the lane cannot satisfy and that the
// runtime identity-conflict abort would only catch after containers run. The
// endpoint key is host:port alone (peer.Host already carries the optional
// port), so two peers of different protocols on the same host:port are treated
// as a conflict -- the strictest rule, matching the runtime dedup posture.
//
// The anchor is reduced to a canonical string. For TLS trust the discriminator
// plus its anchor material (fingerprint or CA-bundle path); for SSH the sorted
// set of "keytype key" entries, so known_hosts order is irrelevant. Steps and
// peers are iterated in declaration order; the first conflicting endpoint
// yields a deterministic error.
func validatePeerAnchors(p *Lane) error {
	seen := map[string]string{} // host:port -> canonical anchor
	for _, s := range p.Steps {
		for _, peer := range s.Peers {
			endpoint := string(peer.Addr().Authority())
			anchor := peerAnchor(peer)
			if prev, ok := seen[endpoint]; ok {
				if prev != anchor {
					return fmt.Errorf(
						"peer endpoint %q declared with conflicting trust anchors", endpoint)
				}
				continue
			}
			seen[endpoint] = anchor
		}
	}
	return nil
}

// peerAnchor returns a canonical string for a peer's trust anchor. Two peers on
// the same endpoint are compatible iff their peerAnchor strings are equal. The
// protocol discriminator is part of the string, so an HTTPS and an SSH anchor
// on one endpoint never compare equal (C-1).
func peerAnchor(peer Peer) string {
	switch x := peer.(type) {
	case endpoint.TLS:
		switch t := x.Trust.(type) {
		case endpoint.Fingerprint:
			return "https/certFingerprint/" + t.Fingerprint
		case endpoint.CABundle:
			return "https/caBundle/" + t.Path
		default:
			return "https/unknown"
		}
	case endpoint.SSH:
		entries := make([]string, len(x.KnownHosts))
		for i, kh := range x.KnownHosts {
			entries[i] = kh.KnownHostsLine()
		}
		sort.Strings(entries)
		return "ssh/" + strings.Join(entries, "\n")
	default:
		return "unknown"
	}
}

// validateBaseSBOMTrustAnchor rejects a lane that declares baseSbomSigners
// without a keyless trust root to anchor base-SBOM verification.
func validateBaseSBOMTrustAnchor(p *Lane) error {
	if len(p.BaseSBOMSigners) == 0 {
		return nil
	}
	if p.Keyless.TrustRoot == nil && p.Keyless.TrustRootRef == "" {
		return fmt.Errorf(
			"lane declares baseSbomSigners but no keyless trust root (trustRoot or trustRootRef); " +
				"base-SBOM verification has no anchor")
	}
	return nil
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

// validateStepKindDisjointness enforces that each step declares exactly one
// of image, imageFromStep, pack, or deploy: the four ways a step's container
// content is determined are mutually exclusive.
func validateStepKindDisjointness(p *Lane) error {
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
			return fmt.Errorf(
				"step %q: exactly one of image, imageFromStep, pack, or deploy required", s.ID)
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
// Defense-in-depth, analogous to ValidatePaths: this runs in the
// validate-lane phase (before build), so `strike validate` and
// `strike run` fail identically on the same invalid input.
func validateResolver(p *Lane) error {
	host := string(p.Resolver.Address.Authority())
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
