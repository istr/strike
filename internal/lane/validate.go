package lane

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
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
	if err := validateDeployMethodImplemented(p); err != nil {
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

// validateDeployArtifactRefs checks a step's deploy artifacts map (ADR-051
// D9): every entry references a known step and, per arm, an existing output
// -- the producing step's image output when output is absent, a declared
// file or directory output when present -- no two entries reference the
// same output, and the registry-method structural rules hold. Kubernetes
// cardinality and containment are settled by the kubernetes rewiring, not
// here.
func validateDeployArtifactRefs(p *Lane, index map[primitive.Identifier]*Step) error {
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		if err := validateArtifactEntries(&s, index); err != nil {
			return err
		}
		if _, ok := s.Deploy.Method.(DeployRegistry); ok {
			if err := validateRegistryArtifacts(&s, index); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateArtifactEntries checks reference integrity and uniqueness of one
// step's artifacts entries, in sorted name order for deterministic errors.
// The uniqueness key reuses the dotted step.output encoding: #Identifier
// excludes '.', so an image arm's "step." cannot collide with a region key.
func validateArtifactEntries(s *Step, index map[primitive.Identifier]*Step) error {
	seen := map[string]primitive.Identifier{}
	for _, name := range slices.Sorted(maps.Keys(s.Deploy.Artifacts)) {
		ref := s.Deploy.Artifacts[name]
		fromStep, ok := index[ref.Step]
		if !ok {
			return fmt.Errorf(
				"step %q: deploy artifact %q references unknown step %q", s.ID, name, ref.Step)
		}
		key := string(ref.Step) + "."
		if ref.Output == nil {
			if fromStep.Output == "" {
				return fmt.Errorf(
					"step %q: deploy artifact %q: step %q declares no image output", s.ID, name, ref.Step)
			}
		} else {
			if findOutput(fromStep, *ref.Output) == nil {
				return fmt.Errorf(
					"step %q: deploy artifact %q: output %q not found in step %q", s.ID, name, *ref.Output, ref.Step)
			}
			key += string(*ref.Output)
		}
		if prev, dup := seen[key]; dup {
			return fmt.Errorf(
				"step %q: deploy artifacts %q and %q reference the same output of step %q", s.ID, prev, name, ref.Step)
		}
		seen[key] = name
	}
	return nil
}

// validateRegistryArtifacts enforces the registry-method structure (ADR-051
// D9): a non-empty map, exactly one image arm (the pushed subject), every
// region packed into the pushed pack image, and no regions on a build-image
// push -- containment in a build image is not verifiable from the lane.
func validateRegistryArtifacts(s *Step, index map[primitive.Identifier]*Step) error {
	if len(s.Deploy.Artifacts) == 0 {
		return fmt.Errorf("step %q: registry deploy requires a non-empty artifacts map", s.ID)
	}
	var imageArm primitive.Identifier
	images := 0
	for _, name := range slices.Sorted(maps.Keys(s.Deploy.Artifacts)) {
		if s.Deploy.Artifacts[name].Output == nil {
			images++
			imageArm = s.Deploy.Artifacts[name].Step
		}
	}
	if images != 1 {
		return fmt.Errorf(
			"step %q: registry deploy requires exactly one image-arm artifacts entry, got %d", s.ID, images)
	}
	pushStep := index[imageArm]
	for _, name := range slices.Sorted(maps.Keys(s.Deploy.Artifacts)) {
		ref := s.Deploy.Artifacts[name]
		if ref.Output == nil {
			continue
		}
		if pushStep.Pack == nil {
			return fmt.Errorf(
				"step %q: deploy artifact %q: file or directory regions require the pushed image %q to be a pack step; containment in a build image is not verifiable", s.ID, name, imageArm)
		}
		if !packCovers(pushStep, ref) {
			return fmt.Errorf(
				"step %q: deploy artifact %q: output %s.%s is not packed into the pushed image %q", s.ID, name, ref.Step, *ref.Output, imageArm)
		}
	}
	return nil
}

// packCovers reports whether the pushed pack step consumes the region's
// output through pack.files, which is what makes the region's bytes part of
// the pushed payload by construction (ADR-051 D9).
func packCovers(pushStep *Step, ref ArtifactRef) bool {
	for _, f := range pushStep.Pack.Files {
		if f.From.Step == ref.Step && f.From.Output == *ref.Output {
			return true
		}
	}
	return false
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
			prefix := out.Path.String() + "/"
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
	seen := map[endpoint.Authority]canonicalAnchor{} // host:port -> canonical anchor
	for _, s := range p.Steps {
		for _, peer := range s.Peers {
			auth := peer.Addr().Authority()
			anchor := peerAnchor(peer)
			if prev, ok := seen[auth]; ok {
				if prev != anchor {
					return fmt.Errorf(
						"peer endpoint %q declared with conflicting trust anchors", auth)
				}
				continue
			}
			seen[auth] = anchor
		}
	}
	return nil
}

// canonicalAnchor is the reduced equality token for a peer's trust anchor:
// two peers on one endpoint are compatible iff their tokens are equal.
type canonicalAnchor string

// peerAnchor returns the canonical anchor for a peer's trust configuration. The
// protocol discriminator is part of the token, so an HTTPS and an SSH anchor on
// one endpoint never compare equal (C-1).
func peerAnchor(peer Peer) canonicalAnchor {
	switch x := peer.(type) {
	case endpoint.TLS:
		switch t := x.Trust.(type) {
		case endpoint.Fingerprint:
			return canonicalAnchor("https/certFingerprint/" + t.Fingerprint.String())
		case endpoint.CABundle:
			return canonicalAnchor("https/caBundle/" + t.Path.String())
		default:
			return "https/unknown"
		}
	case endpoint.SSH:
		entries := make([]string, len(x.KnownHosts))
		for i, kh := range x.KnownHosts {
			entries[i] = kh.KnownHostsLine()
		}
		sort.Strings(entries)
		return canonicalAnchor("ssh/" + strings.Join(entries, "\n"))
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

// validateDeployMethodImplemented rejects a declared deploy method that has no
// execution path. The kubernetes method is a control-plane act against the
// cluster API (ADR-054); its container-based implementation was removed and the
// replacement is not built. Rejecting here rather than at run time means the
// author learns it from `strike validate`, and the method keeps its schema arm
// and its dispatch so the rebuild reuses both unchanged.
func validateDeployMethodImplemented(p *Lane) error {
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		if _, ok := s.Deploy.Method.(DeployKubernetes); ok {
			return fmt.Errorf(
				"step %q: kubernetes deploy method is not yet implemented (ADR-054)", s.ID)
		}
	}
	return nil
}

// validateResolver enforces the two constraints on the declared DoT resolver
// that the schema cannot express. The IP must be a canonical address literal:
// the resolver is the lane's own resolution authority and cannot resolve a
// name to reach itself, and the CUE alphabet admits a few hostnames by
// coincidence. The ADN must not be an address literal: RFC 8310 section 3
// excludes IP addresses as server identifiers, so an address in that field
// would name a credential nothing can present.
//
// Defense-in-depth, analogous to ValidatePaths: this runs in the
// validate-lane phase (before build), so `strike validate` and `strike run`
// fail identically on the same invalid input. The IP parse is the same
// DialTarget projection the dialer uses, so the check and the use cannot
// diverge.
func validateResolver(p *Lane) error {
	if p.Resolver.ADN == "" {
		return fmt.Errorf("resolver: adn required")
	}
	if _, err := netip.ParseAddr(p.Resolver.ADN.String()); err == nil {
		return fmt.Errorf(
			"resolver adn %q is an address literal; the adn is the "+
				"authentication domain name the certificate is verified "+
				"against, and RFC 8310 section 3 excludes addresses from "+
				"that role -- put the address in ip",
			p.Resolver.ADN)
	}
	if _, err := p.Resolver.DialTarget(); err != nil {
		return err
	}
	return nil
}
