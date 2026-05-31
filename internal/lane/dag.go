// Package lane defines the pipeline schema, DAG construction,
// and execution state for strike lanes.
package lane

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// parseRef splits a "step_name.output_name" reference into its parts.
func parseRef(ref string) (step, output string, err error) {
	parts := strings.SplitN(ref, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid reference %q: expected step_name.output_name", ref)
	}
	return parts[0], parts[1], nil
}

// InputEdge is a fully resolved step.inputs[i] entry.
// FromStep and FromOutput are guaranteed non-nil by Build.
// Subpath is nil when the entire producer output is mounted.
type InputEdge struct {
	FromStep   *Step
	FromOutput *OutputSpec
	Subpath    *RelPath // == InputRef.Subpath; nil means whole output
	Mount      AbsPath  // == InputRef.Mount
}

// PackFileEdge is a fully resolved step.pack.files[i] entry.
type PackFileEdge struct {
	FromStep   *Step
	FromOutput *OutputSpec
	Dest       AbsPath // == PackFile.Dest
}

// DeployArtifactEdge is a fully resolved step.deploy.artifacts[name] entry.
type DeployArtifactEdge struct {
	FromStep     *Step
	FromOutput   *OutputSpec
	ArtifactName string
}

// ImageFromEdge is a fully resolved step.image_from.
type ImageFromEdge struct {
	FromStep   *Step
	FromOutput *OutputSpec
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
		if _, exists := d.Steps[string(s.Name)]; exists {
			return nil, fmt.Errorf("duplicate step name: %q", s.Name)
		}
		d.Steps[string(s.Name)] = s
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

	order, err := kahnSort(d)
	if err != nil {
		return nil, err
	}
	d.Order = order
	return d, nil
}

func (d *DAG) resolveImageFromEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		if s.ImageFrom == nil {
			continue
		}
		from := s.ImageFrom.Step
		fromStep, ok := d.Steps[from]
		if !ok {
			return fmt.Errorf("step %q: image_from references unknown step %q", name, from)
		}
		out := findOutput(fromStep, s.ImageFrom.Output)
		if out == nil {
			return fmt.Errorf("step %q: image_from output %q not found in step %q",
				name, s.ImageFrom.Output, from)
		}
		if out.Type != "image" {
			return fmt.Errorf("step %q: image_from output %q in step %q is %q, not image",
				name, out.Name, from, out.Type)
		}
		d.ImageFromEdges[name] = ImageFromEdge{FromStep: fromStep, FromOutput: out}
		d.addEdge(name, from)
	}
	return nil
}

func (d *DAG) resolveInputEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		for _, inp := range s.Inputs {
			refStep, refOutput, err := parseRef(inp.From)
			if err != nil {
				return fmt.Errorf("step %q: input at %q: %w", name, inp.Mount, err)
			}
			fromStep, ok := d.Steps[refStep]
			if !ok {
				return fmt.Errorf("step %q: input at %q references unknown step %q",
					name, inp.Mount, refStep)
			}
			out := findOutput(fromStep, refOutput)
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
			d.addEdge(name, refStep)
		}
	}
	return nil
}

func (d *DAG) resolvePackEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
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
	stepName, outputName, err := parseRef(f.From)
	if err != nil {
		return fmt.Errorf("step %q: pack file: %w", name, err)
	}
	fromStep, ok := d.Steps[stepName]
	if !ok {
		return fmt.Errorf("step %q: pack file from %q: unknown step %q", name, f.From, stepName)
	}
	out := findOutput(fromStep, outputName)
	if out == nil {
		return fmt.Errorf("step %q: pack file from %q: output %q not found in step %q",
			name, f.From, outputName, stepName)
	}
	d.PackFileEdges[name] = append(d.PackFileEdges[name], PackFileEdge{
		Dest:       f.Dest,
		FromStep:   fromStep,
		FromOutput: out,
	})
	d.addEdge(name, stepName)
	return nil
}

// findOutput returns a pointer to the OutputSpec with the given name,
// or nil if not found. The returned pointer aliases into s.Outputs,
// so callers must not mutate s after Build returns.
func findOutput(s *Step, name string) *OutputSpec {
	for i := range s.Outputs {
		if s.Outputs[i].Name == name {
			return &s.Outputs[i]
		}
	}
	return nil
}

func (d *DAG) resolveDeployEdges(p *Lane) error {
	for _, s := range p.Steps {
		name := string(s.Name)
		if s.Deploy == nil {
			continue
		}
		for artName, artRef := range s.Deploy.Artifacts {
			stepName, outputName, err := parseRef(artRef.From)
			if err != nil {
				return fmt.Errorf("step %q: deploy artifact %q: %w", name, artName, err)
			}
			fromStep, ok := d.Steps[stepName]
			if !ok {
				return fmt.Errorf("step %q: deploy artifact %q references unknown step %q",
					name, artName, stepName)
			}
			out := findOutput(fromStep, outputName)
			if out == nil {
				return fmt.Errorf("step %q: deploy artifact %q: output %q not found in step %q",
					name, artName, outputName, stepName)
			}
			d.DeployEdges[name] = append(d.DeployEdges[name], DeployArtifactEdge{
				ArtifactName: artName,
				FromStep:     fromStep,
				FromOutput:   out,
			})
			d.addEdge(name, stepName)
		}
	}
	return nil
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
			return fmt.Errorf("step %q: provenance.path %q: %w", s.Name, provPath, err)
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
				s.Name, provPath)
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
		dependents := d.reverse[string(s.Name)]
		if len(dependents) == 0 {
			continue
		}
		sorted := append([]string(nil), dependents...)
		sort.Strings(sorted)
		return fmt.Errorf("deploy step %q must be a DAG leaf but is depended on by %v",
			s.Name, sorted)
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
// mount that image at the desired root. This keeps mount topology trivial
// and makes composition explicit and content-addressed.
func (d *DAG) validateMountDisjointness(p *Lane) error {
	for _, s := range p.Steps {
		edges := d.InputEdges[string(s.Name)]
		if len(edges) < 2 {
			continue
		}
		for i := range edges {
			for j := i + 1; j < len(edges); j++ {
				a, b := edges[i].Mount, edges[j].Mount
				if mountsConflict(a, b) {
					return fmt.Errorf(
						"step %q: input mounts %q and %q overlap; compose them in a pack step",
						s.Name, a, b)
				}
			}
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
func mountsConflict(a, b AbsPath) bool {
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

func (d *DAG) addEdge(from, to string) {
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
// implementation language. See docs/DESIGN-PRINCIPLES.md
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

// Tree renders the DAG as a tree structure.
func (d *DAG) Tree() string {
	var sb strings.Builder

	// Roots: steps without dependencies
	roots := []string{}
	for name := range d.Steps {
		if len(d.edges[name]) == 0 {
			roots = append(roots, name)
		}
	}

	for i, root := range roots {
		last := i == len(roots)-1
		prefix := ""
		connector := "+-- "
		if last {
			connector = "`-- "
		}
		sb.WriteString(connector + root + "\n")
		d.treeNode(&sb, root, prefix, last)
	}

	return sb.String()
}

func (d *DAG) treeNode(sb *strings.Builder, node, prefix string, lastParent bool) {
	dependents := d.reverse[node]
	childPrefix := prefix
	if lastParent {
		childPrefix += "    "
	} else {
		childPrefix += "|   "
	}

	for i, dep := range dependents {
		last := i == len(dependents)-1
		connector := "+-- "
		if last {
			connector = "`-- "
		}
		// Show dependencies when more than one
		deps := d.edges[dep]
		annotation := ""
		if len(deps) > 1 {
			annotation = " (" + strings.Join(deps, ", ") + ")"
		}
		sb.WriteString(childPrefix + connector + dep + annotation + "\n")
		d.treeNode(sb, dep, childPrefix, last)
	}
}
