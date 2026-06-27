// Package lane defines the pipeline schema, DAG construction,
// and execution state for strike lanes.
package lane

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// InputEdge is a fully resolved step.inputs[i] entry.
// FromStep and FromOutput are guaranteed non-nil by Build.
// Subpath is nil when the entire producer output is mounted.
type InputEdge struct {
	FromStep   *Step
	FromOutput *FileOutput
	Subpath    *primitive.RelPath // == InputRef.Subpath; nil means whole output
	Mount      primitive.AbsPath  // == InputRef.Mount
}

// PackFileEdge is a fully resolved step.pack.files[i] entry.
type PackFileEdge struct {
	FromStep   *Step
	FromOutput *FileOutput
	Dest       primitive.AbsPath // == PackFile.Dest
}

// DeployArtifactEdge is a fully resolved step.deploy.artifacts[name] entry.
// Image marks the step-image arm of the from disjunction (FromOutput is nil);
// otherwise FromOutput names the file or directory output.
type DeployArtifactEdge struct {
	FromStep     *Step
	FromOutput   *FileOutput
	ArtifactName string
	Image        bool
}

// ImageFromEdge is a fully resolved step.image_from_step. Resolved by step: the
// producing step's single image output, addressed by step (no output name).
type ImageFromEdge struct {
	FromStep *Step
}

// DAG is the directed acyclic graph of step dependencies in a lane.
type DAG struct {
	Steps          map[string]*Step
	InputEdges     map[string][]InputEdge // key: consuming step name
	PackFileEdges  map[string][]PackFileEdge
	DeployEdges    map[string][]DeployArtifactEdge
	ImageFromEdges map[string]ImageFromEdge // one per step, if any
	edges          map[string][]string      // step -> []dependencies
	reverse        map[string][]string      // dep -> []dependents
	// Order is the lexicographically smallest valid topological
	// execution order of the lane's steps, computed by
	// kahnSort. The same step graph always produces the same
	// Order across runs, machines, Go versions, and
	// implementation languages; see kahnSort's doc comment and
	// DESIGN-PRINCIPLES.md "Reproducibility is enforced, not
	// hoped for".
	Order []string
}

// Build constructs a DAG from a Lane definition, resolving all inter-step edges.
func Build(p *Lane) (*DAG, error) {
	d := &DAG{
		Steps:          make(map[string]*Step),
		InputEdges:     make(map[string][]InputEdge),
		PackFileEdges:  make(map[string][]PackFileEdge),
		DeployEdges:    make(map[string][]DeployArtifactEdge),
		ImageFromEdges: make(map[string]ImageFromEdge),
		edges:          make(map[string][]string),
		reverse:        make(map[string][]string),
	}

	for i := range p.Steps {
		s := &p.Steps[i]
		if _, exists := d.Steps[string(s.ID)]; exists {
			return nil, fmt.Errorf("duplicate step name: %q", s.ID)
		}
		d.Steps[string(s.ID)] = s
	}

	if err := validateOutputIDDisjointness(p); err != nil {
		return nil, err
	}

	if err := d.resolveImageFromEdges(p); err != nil {
		return nil, err
	}
	if err := d.resolveInputEdges(p); err != nil {
		return nil, err
	}
	if err := d.resolvePackEdges(p); err != nil {
		return nil, err
	}
	if err := d.resolveDeployEdges(p); err != nil {
		return nil, err
	}

	if err := d.validateProvenancePaths(p); err != nil {
		return nil, err
	}
	if err := d.validateMountDisjointness(p); err != nil {
		return nil, err
	}
	if err := d.validateDeployLeaves(p); err != nil {
		return nil, err
	}
	if err := d.validatePeerAnchors(p); err != nil {
		return nil, err
	}
	if err := d.validateBaseSBOMTrustAnchor(p); err != nil {
		return nil, err
	}

	order, err := kahnSort(d)
	if err != nil {
		return nil, err
	}
	d.Order = order
	return d, nil
}

func (d *DAG) resolveImageFromEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.ID)
		if s.ImageFromStep == nil {
			continue
		}
		from := *s.ImageFromStep
		fromStep, ok := d.Steps[string(from)]
		if !ok {
			return fmt.Errorf("step %q: imageFromStep references unknown step %q", name, from)
		}
		if fromStep.Output == "" {
			return fmt.Errorf("step %q: imageFromStep %q declares no image output", name, from)
		}
		d.ImageFromEdges[name] = ImageFromEdge{FromStep: fromStep}
		d.addEdge(name, string(from))
	}
	return nil
}

func (d *DAG) resolveInputEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.ID)
		for _, inp := range s.Inputs {
			refStep := inp.From.Step
			refOutput := inp.From.Output
			fromStep, ok := d.Steps[string(refStep)]
			if !ok {
				return fmt.Errorf("step %q: input at %q references unknown step %q",
					name, inp.Mount, refStep)
			}
			out := findOutput(fromStep, string(refOutput))
			if out == nil {
				return fmt.Errorf("step %q: input at %q: output %q not found in step %q",
					name, inp.Mount, refOutput, refStep)
			}
			if inp.Subpath != nil && out.Type == "file" {
				return fmt.Errorf("step %q: input at %q: subpath %q not allowed on file output %q.%q",
					name, inp.Mount, *inp.Subpath, refStep, refOutput)
			}
			d.InputEdges[name] = append(d.InputEdges[name], InputEdge{
				Mount:      inp.Mount,
				Subpath:    inp.Subpath,
				FromStep:   fromStep,
				FromOutput: out,
			})
			d.addEdge(name, string(refStep))
		}
	}
	return nil
}

func (d *DAG) resolvePackEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.ID)
		if s.Pack == nil {
			continue
		}
		for _, f := range s.Pack.Files {
			if err := d.resolvePackFileEdge(name, f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *DAG) resolvePackFileEdge(name string, f PackFile) error {
	stepID := f.From.Step
	outputID := f.From.Output
	fromStep, ok := d.Steps[string(stepID)]
	if !ok {
		return fmt.Errorf("step %q: pack file references unknown step %q", name, stepID)
	}
	out := findOutput(fromStep, string(outputID))
	if out == nil {
		return fmt.Errorf("step %q: pack file output %q not found in step %q",
			name, outputID, stepID)
	}
	d.PackFileEdges[name] = append(d.PackFileEdges[name], PackFileEdge{
		Dest:       f.Dest,
		FromStep:   fromStep,
		FromOutput: out,
	})
	d.addEdge(name, string(stepID))
	return nil
}

// findOutput returns a pointer to the FileOutput with the given name,
// or nil if not found. The returned pointer aliases into s.Outputs,
// so callers must not mutate s after Build returns.
func findOutput(s *Step, name string) *FileOutput {
	for i := range s.Outputs {
		if string(s.Outputs[i].ID) == name {
			return &s.Outputs[i]
		}
	}
	return nil
}

func (d *DAG) resolveDeployEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.ID)
		if s.Deploy == nil {
			continue
		}
		for artName, artRef := range s.Deploy.Artifacts {
			edge, stepID, err := d.resolveDeployArtifact(name, artName, artRef.From)
			if err != nil {
				return err
			}
			d.DeployEdges[name] = append(d.DeployEdges[name], edge)
			d.addEdge(name, stepID)
		}
	}
	return nil
}

// resolveDeployArtifact resolves one deploy.artifacts[name].from disjunction:
// a StepImageRef (the producing step's image, by step) or an OutputRef (a named
// file or directory output, by step+output).
func (d *DAG) resolveDeployArtifact(name, artName string, src ArtifactSource) (DeployArtifactEdge, string, error) {
	switch ref := src.(type) {
	case StepImageRef:
		fromStep, ok := d.Steps[string(ref.Step)]
		if !ok {
			return DeployArtifactEdge{}, "", fmt.Errorf(
				"step %q: deploy artifact %q references unknown step %q", name, artName, ref.Step)
		}
		if fromStep.Output == "" {
			return DeployArtifactEdge{}, "", fmt.Errorf(
				"step %q: deploy artifact %q: step %q declares no image output", name, artName, ref.Step)
		}
		return DeployArtifactEdge{ArtifactName: artName, FromStep: fromStep, Image: true}, string(ref.Step), nil
	case OutputRef:
		fromStep, ok := d.Steps[string(ref.Step)]
		if !ok {
			return DeployArtifactEdge{}, "", fmt.Errorf(
				"step %q: deploy artifact %q references unknown step %q", name, artName, ref.Step)
		}
		out := findOutput(fromStep, string(ref.Output))
		if out == nil {
			return DeployArtifactEdge{}, "", fmt.Errorf(
				"step %q: deploy artifact %q: output %q not found in step %q",
				name, artName, ref.Output, ref.Step)
		}
		return DeployArtifactEdge{ArtifactName: artName, FromStep: fromStep, FromOutput: out}, string(ref.Step), nil
	default:
		return DeployArtifactEdge{}, "", fmt.Errorf(
			"step %q: deploy artifact %q: unknown source kind %q", name, artName, src.SourceKind())
	}
}

// validateProvenancePaths checks that each step's provenance.path
// (if declared) is relative, canonical, and lies within a declared output.
// A whole-workdir output (path absent) contains any provenance file.
func (d *DAG) validateProvenancePaths(p *Lane) error {
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
			if provPath == *out.Path || provPath.HasPrefix(string(*out.Path)+"/") {
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

// validateDeployLeaves enforces ADR-039 D2: a deploy step is a DAG leaf.
// No step may depend on a deploy step. The schema already forbids outputs
// on a deploy step (so any reference to one also fails output resolution),
// but this check yields a precise error and holds even for a DAG built
// without going through Parse. Steps are iterated in lane order and the
// dependent list is sorted, so the error message is deterministic.
func (d *DAG) validateDeployLeaves(p *Lane) error {
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		dependents := d.reverse[string(s.ID)]
		if len(dependents) == 0 {
			continue
		}
		sorted := append([]string(nil), dependents...)
		sort.Strings(sorted)
		return fmt.Errorf("deploy step %q must be a DAG leaf but is depended on by %v",
			s.ID, sorted)
	}
	return nil
}

// ValidateLeavesAreDeploys enforces that every DAG leaf is a deploy
// step (ADR-039 D5). A non-deploy step whose output no other step
// consumes is a dangling terminal build: it contributes to no
// attestation, and -- because a leaf has no successor whose execution
// its failure could prevent -- it cannot gate the deploy it might be
// meant to guard. A check or QA step is therefore expressed as a
// predecessor in the artifact's data path (it consumes the artifact
// and produces an output the deploy consumes), so its failure stops
// the deploy. Together with validateDeployLeaves (a deploy step is a
// leaf, ADR-039 D2) this makes "leaf" and "deploy step" coextensive:
// a lane's leaves are exactly its deploy targets.
//
// This is a lane-validity policy that needs the resolved graph, so it
// is deliberately NOT called from Build (which stays usable for graph-
// mechanism tests that build partial graphs). The CLI calls it as part
// of the single validation gate every subcommand passes through. Steps
// are iterated in lane order so the first error is deterministic.
func (d *DAG) ValidateLeavesAreDeploys(p *Lane) error {
	for _, s := range p.Steps {
		if s.Deploy != nil {
			continue
		}
		if len(d.reverse[string(s.ID)]) == 0 {
			return fmt.Errorf("step %q is a non-deploy DAG leaf: nothing consumes "+
				"its output and it is not a deploy step; a gate must produce an "+
				"output the deploy consumes so it sits in the chain (ADR-039 D5)",
				s.ID)
		}
	}
	return nil
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
func (d *DAG) validatePeerAnchors(p *Lane) error {
	seen := map[string]string{} // host:port -> canonical anchor
	for _, s := range p.Steps {
		for _, peer := range s.Peers {
			endpoint := peer.Addr().Authority()
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
			entries[i] = kh.KeyType + " " + string(kh.Key)
		}
		sort.Strings(entries)
		return "ssh/" + strings.Join(entries, "\n")
	default:
		return "unknown"
	}
}

// validateMountDisjointness checks that input mounts within the same step
// do not nest. Two mounts a and b conflict iff a == b, or a is a path
// prefix of b, or b is a path prefix of a. Workdir is not a mount and
// is excluded from this check.
//
// When a step legitimately needs multiple sources to appear at related
// container paths (e.g. /work + /work/node_modules), the user must compose
// them in a separate pack step that produces a single image output, then
// mount that image at the desired root. This keeps mount topology trivial
// and makes composition explicit and content-addressed.
func (d *DAG) validateMountDisjointness(p *Lane) error {
	for _, s := range p.Steps {
		edges := d.InputEdges[string(s.ID)]
		if len(edges) < 2 {
			continue
		}
		for i := range edges {
			for j := i + 1; j < len(edges); j++ {
				a, b := edges[i].Mount, edges[j].Mount
				if mountsConflict(a, b) {
					return fmt.Errorf(
						"step %q: input mounts %q and %q overlap; compose them in a pack step",
						s.ID, a, b)
				}
			}
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
		seen := make(map[string]struct{}, len(s.Outputs))
		for _, out := range s.Outputs {
			if _, dup := seen[string(out.ID)]; dup {
				return fmt.Errorf("step %q: duplicate output id %q", s.ID, out.ID)
			}
			seen[string(out.ID)] = struct{}{}
		}
	}
	return nil
}

// mountsConflict reports whether two absolute container paths overlap
// in a way that would make their bind mounts nested.
//
//	"/a"     and "/a"      -> conflict (identical)
//	"/a"     and "/a/b"    -> conflict (a is prefix of b)
//	"/a/b"   and "/a"      -> conflict (a is prefix of b)
//	"/a/b"   and "/a/c"    -> no conflict (siblings)
//	"/a"     and "/abc"    -> no conflict (NOT a prefix in path terms)
func mountsConflict(a, b primitive.AbsPath) bool {
	ca := path.Clean(string(a))
	cb := path.Clean(string(b))
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

// addEdge records that step "from" depends on step "to". The
// dependency relation modelled by edges/reverse is a set, not a
// multiset: a step that references the same producer through several
// inputs, pack files, or deploy artifacts depends on it exactly once.
// The typed edge maps (InputEdges, PackFileEdges, DeployEdges,
// ImageFromEdges) carry the full per-reference detail; edges/reverse
// carry only the collapsed relation that kahnSort, Tree, and the
// attestation predecessor chain consume. Idempotent: a repeated
// (from, to) pair is a no-op. Because both slices are only ever
// appended together through this function, the presence of "to" in
// edges[from] implies the presence of "from" in reverse[to], so one
// membership check guards both.
func (d *DAG) addEdge(from, to string) {
	if slices.Contains(d.edges[from], to) {
		return
	}
	d.edges[from] = append(d.edges[from], to)
	d.reverse[to] = append(d.reverse[to], from)
}

// kahnSort computes the lexicographically smallest valid
// topological order of d's steps.
//
// Algorithm. Kahn's topological sort with a ready set sorted
// at every extraction. The ready set initially contains all
// zero-in-degree steps. At each iteration, the
// lexicographically smallest member is extracted and appended
// to the order; its dependents have their in-degrees
// decremented, and any dependent whose in-degree reaches zero
// joins the ready set. The loop terminates when the ready set
// is empty.
//
// String comparison is byte-wise (Go sort.Strings semantics).
// Strike step names are constrained to printable ASCII by the
// CUE schema, so byte-wise ordering is equivalent to
// lexicographic ordering for any valid input. The comparator
// is intentionally identical to Rust's default Ord on &str
// (also byte-wise), so cross-implementation verifiers match
// without depending on locale or Unicode collation tables.
//
// Property. The same step graph -- defined by the set of step
// names and the set of edges between them -- always produces
// the same Order, regardless of YAML declaration order, Go
// map-iteration randomness, runtime, machine, or
// implementation language. See DESIGN-PRINCIPLES.md
// "Reproducibility is enforced, not hoped for".
//
// Returns an error if the graph is cyclic.
func kahnSort(d *DAG) ([]string, error) {
	// Compute in-degree for every step from its declared
	// inputs. The map-iteration here is read-only and does
	// not leak into the output.
	inDegree := make(map[string]int, len(d.Steps))
	for name := range d.Steps {
		inDegree[name] = len(d.edges[name])
	}

	// Collect initially-ready steps. The map-iteration order
	// here also does not affect the output, because the ready
	// slice is sorted at every extraction below.
	ready := make([]string, 0, len(d.Steps))
	for name, deg := range inDegree {
		if deg == 0 {
			ready = append(ready, name)
		}
	}

	order := make([]string, 0, len(d.Steps))
	for len(ready) > 0 {
		// Sort the ready set and extract its smallest member.
		// This is the single point where the lex-smallest
		// property is enforced; do not remove this sort even
		// if "ready was already sorted last iteration" appears
		// to be invariant. New dependents are appended without
		// re-sorting, so the invariant does not hold.
		sort.Strings(ready)
		node := ready[0]
		ready = ready[1:]
		order = append(order, node)

		// Decrement dependents' in-degrees; any that reach
		// zero join the ready set for the next iteration.
		// The iteration order over d.reverse[node] does not
		// affect the output, because joining the ready set is
		// commutative.
		for _, dependent := range d.reverse[node] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				ready = append(ready, dependent)
			}
		}
	}

	if len(order) != len(d.Steps) {
		return nil, fmt.Errorf("cyclic dependency in lane graph")
	}
	return order, nil
}

// CollectPeers returns peer declarations for fromStep and all its
// transitive predecessors, keyed by step name. Steps without declared
// peers are omitted from the result. Used by deploy attestation to
// record the full network exposure of the build chain. Nil-safe:
// callers may invoke this on a nil receiver and receive a non-nil
// empty map (matching the schema requirement that Attestation.peers
// be a present map).
func (d *DAG) CollectPeers(fromStep string) map[string][]Peer {
	peers := map[string][]Peer{}
	if d == nil {
		return peers
	}
	visited := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		if step := d.Steps[name]; step != nil && len(step.Peers) > 0 {
			peers[name] = step.Peers
		}
		for _, dep := range d.edges[name] {
			walk(dep)
		}
	}
	walk(fromStep)
	return peers
}

// Tree renders the DAG as an ASCII tree rooted at the lane's sinks --
// the steps that no other step depends on. A deploy step is always a
// sink (ADR-039 D2), so every deploy target is a root; its subtree is
// that target's transitive dependency chain, i.e. exactly the
// predecessor set its attestation records, in the same edge direction
// CollectPeers walks. A non-deploy terminal artifact is also a sink and
// is shown as its own root, so nothing in the graph is hidden.
//
// The graph is a DAG, not a tree: a dependency reachable through more
// than one path is printed in full at its first occurrence and as a
// back-reference "name (*)" -- without its subtree -- thereafter, so no
// subtree is duplicated. Sinks and each node's dependencies are sorted,
// so the output is deterministic for a given graph regardless of
// map-iteration order in the resolvers (resolveDeployEdges iterates a
// map). See DESIGN-PRINCIPLES.md "Reproducibility is enforced, not
// hoped for".
func (d *DAG) Tree() string {
	var sb strings.Builder

	// Roots: sinks (steps no other step depends on), sorted for
	// deterministic output.
	roots := []string{}
	for name := range d.Steps {
		if len(d.reverse[name]) == 0 {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)

	visited := make(map[string]bool, len(d.Steps))
	for i, root := range roots {
		last := i == len(roots)-1
		connector := "+-- "
		if last {
			connector = "`-- "
		}
		sb.WriteString(connector + root + "\n")
		visited[root] = true
		d.treeNode(&sb, root, "", last, visited)
	}

	return sb.String()
}

func (d *DAG) treeNode(sb *strings.Builder, node, prefix string, lastParent bool, visited map[string]bool) {
	// Copy and sort the node's dependencies so the traversal order -- and
	// thus which occurrence of a shared dependency is the full one -- is
	// deterministic. Do not sort d.edges[node] in place; it is shared.
	deps := append([]string(nil), d.edges[node]...)
	sort.Strings(deps)

	childPrefix := prefix
	if lastParent {
		childPrefix += "    "
	} else {
		childPrefix += "|   "
	}

	for i, dep := range deps {
		last := i == len(deps)-1
		connector := "+-- "
		if last {
			connector = "`-- "
		}
		if visited[dep] {
			// Already printed in full elsewhere. Emit a back-reference
			// and do not recurse, so the shared subtree is not repeated.
			sb.WriteString(childPrefix + connector + dep + " (*)\n")
			continue
		}
		visited[dep] = true
		sb.WriteString(childPrefix + connector + dep + "\n")
		d.treeNode(sb, dep, childPrefix, last, visited)
	}
}

// PackBaseRefs returns the distinct, digest-pinned base image references of the
// pack steps in the transitive predecessor sub-tree of fromStep, sorted for
// deterministic attestation output. It mirrors State.CollectProvenance's walk
// over the dependency edges (excluding fromStep itself), reading PackSpec.Base
// for each pack step reached. These are the base images whose signed SBOMs the
// deploy step's producer-side verification considers.
func (d *DAG) PackBaseRefs(fromStep string) []primitive.ImageRef {
	if d == nil {
		return nil
	}
	visited := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		for _, dep := range d.edges[name] {
			walk(dep)
		}
	}
	walk(fromStep)
	delete(visited, fromStep)

	seen := map[primitive.ImageRef]bool{}
	var out []primitive.ImageRef
	for name := range visited {
		s := d.Steps[name]
		if s == nil || s.Pack == nil {
			continue
		}
		if !seen[s.Pack.Base] {
			seen[s.Pack.Base] = true
			out = append(out, s.Pack.Base)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// validateBaseSBOMTrustAnchor enforces that a lane declaring base SBOM signers
// also declares a resolvable keyless trust root: producer-side base-SBOM
// signature verification has nothing to verify against otherwise. Like a mutable
// image reference, declaring signers without an anchor is a structural error
// caught at lane build, not a deploy-time surprise. The receiver is unused, kept
// for symmetry with the other build validations.
func (d *DAG) validateBaseSBOMTrustAnchor(p *Lane) error {
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
