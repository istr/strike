// Package lane defines the pipeline schema, DAG construction,
// and execution state for strike lanes.
package lane

import (
	"fmt"
	"iter"
	"slices"
	"sort"
	"strings"

	"github.com/istr/strike/internal/primitive"
)

// DAG is the directed acyclic graph of step dependencies in a lane.
type DAG struct {
	index   map[primitive.Identifier]*Step                  // step id -> step, from Parse
	edges   map[primitive.Identifier][]primitive.Identifier // step -> []dependencies
	reverse map[primitive.Identifier][]primitive.Identifier // dep -> []dependents
	// order is the lexicographically smallest valid topological
	// execution order of the lane's steps, computed by
	// kahnSort. The same step graph always produces the same
	// order across runs, machines, Go versions, and
	// implementation languages; see kahnSort's doc comment and
	// DESIGN-PRINCIPLES.md "Reproducibility is enforced, not
	// hoped for". Exposed read-only via Order().
	order []primitive.Identifier
}

// Build constructs a DAG from a Lane definition, resolving all inter-step edges.
func Build(p *Lane, index map[primitive.Identifier]*Step) (*DAG, error) {
	d := &DAG{
		index:   index,
		edges:   make(map[primitive.Identifier][]primitive.Identifier),
		reverse: make(map[primitive.Identifier][]primitive.Identifier),
	}

	d.buildAdjacency(p)

	if err := d.validateDeployLeaves(p); err != nil {
		return nil, err
	}

	order, err := kahnSort(d)
	if err != nil {
		return nil, err
	}
	d.order = order
	return d, nil
}

// buildAdjacency records the dependency edge from each step to every step it
// references -- image-from, inputs, pack files, and deploy artifacts -- from the
// reference identifiers alone. Reference integrity is a precondition
// (ValidateLane), so an unknown reference has already been rejected and an
// unknown deploy-source kind cannot reach this point.
func (d *DAG) buildAdjacency(p *Lane) {
	for _, s := range p.Steps {
		if s.ImageFromStep != nil {
			d.addEdge(s.ID, *s.ImageFromStep)
		}
		for _, inp := range s.Inputs {
			d.addEdge(s.ID, inp.From.Step)
		}
		if s.Pack != nil {
			for _, f := range s.Pack.Files {
				d.addEdge(s.ID, f.From.Step)
			}
		}
		if s.Deploy != nil {
			for _, art := range s.Deploy.Artifacts {
				switch src := art.From.(type) {
				case StepImageRef:
					d.addEdge(s.ID, src.Step)
				case OutputRef:
					d.addEdge(s.ID, src.Step)
				}
			}
		}
	}
}

// Order returns the lexicographically smallest valid topological execution
// order of the lane's steps (see the order field and kahnSort).
func (d *DAG) Order() []primitive.Identifier {
	return d.order
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
		dependents := d.reverse[s.ID]
		if len(dependents) == 0 {
			continue
		}
		sorted := append([]primitive.Identifier(nil), dependents...)
		slices.Sort(sorted)
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
		if len(d.reverse[s.ID]) == 0 {
			return fmt.Errorf("step %q is a non-deploy DAG leaf: nothing consumes "+
				"its output and it is not a deploy step; a gate must produce an "+
				"output the deploy consumes so it sits in the chain (ADR-039 D5)",
				s.ID)
		}
	}
	return nil
}

// addEdge records that step "from" depends on step "to". The
// dependency relation modelled by edges/reverse is a set, not a
// multiset: a step that references the same producer through several
// inputs, pack files, or deploy artifacts depends on it exactly once.
// edges/reverse carry only the collapsed relation that kahnSort, Tree,
// and the attestation predecessor chain consume. Idempotent: a
// repeated (from, to) pair is a no-op. Because both slices are only
// ever appended together through this function, the presence of "to"
// in edges[from] implies the presence of "from" in reverse[to], so one
// membership check guards both.
func (d *DAG) addEdge(from, to primitive.Identifier) {
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
func kahnSort(d *DAG) ([]primitive.Identifier, error) {
	// Compute in-degree for every step from its declared
	// inputs. The map-iteration here is read-only and does
	// not leak into the output.
	inDegree := make(map[primitive.Identifier]int, len(d.index))
	for name := range d.index {
		inDegree[name] = len(d.edges[name])
	}

	// Collect initially-ready steps. The map-iteration order
	// here also does not affect the output, because the ready
	// slice is sorted at every extraction below.
	ready := make([]primitive.Identifier, 0, len(d.index))
	for name, deg := range inDegree {
		if deg == 0 {
			ready = append(ready, name)
		}
	}

	order := make([]primitive.Identifier, 0, len(d.index))
	for len(ready) > 0 {
		// Sort the ready set and extract its smallest member.
		// This is the single point where the lex-smallest
		// property is enforced; do not remove this sort even
		// if "ready was already sorted last iteration" appears
		// to be invariant. New dependents are appended without
		// re-sorting, so the invariant does not hold.
		slices.Sort(ready)
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

	if len(order) != len(d.index) {
		return nil, fmt.Errorf("cyclic dependency in lane graph")
	}
	return order, nil
}

// predecessors yields fromStep and its transitive predecessors over the
// dependency adjacency, each id exactly once. includeFrom selects whether
// fromStep itself is yielded. The attestation walks (peers, base refs,
// provenance) consume this; each keys a map or sorts its result, so the yield
// order is unspecified. Nil-safe: a nil receiver yields nothing.
func (d *DAG) predecessors(fromStep primitive.Identifier, includeFrom bool) iter.Seq[primitive.Identifier] {
	return func(yield func(primitive.Identifier) bool) {
		if d == nil {
			return
		}
		visited := map[primitive.Identifier]bool{}
		var walk func(name primitive.Identifier) bool
		walk = func(name primitive.Identifier) bool {
			if visited[name] {
				return true
			}
			visited[name] = true
			if includeFrom || name != fromStep {
				if !yield(name) {
					return false
				}
			}
			for _, dep := range d.edges[name] {
				if !walk(dep) {
					return false
				}
			}
			return true
		}
		walk(fromStep)
	}
}

// CollectPeers returns peer declarations for fromStep and all its
// transitive predecessors, keyed by step name. Steps without declared
// peers are omitted from the result. Used by deploy attestation to
// record the full network exposure of the build chain. Nil-safe:
// callers may invoke this on a nil receiver and receive a non-nil
// empty map (matching the schema requirement that Attestation.peers
// be a present map).
func (d *DAG) CollectPeers(fromStep primitive.Identifier) map[primitive.Identifier][]Peer {
	peers := map[primitive.Identifier][]Peer{}
	for name := range d.predecessors(fromStep, true) {
		if step := d.index[name]; step != nil && len(step.Peers) > 0 {
			peers[name] = step.Peers
		}
	}
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
// map-iteration order in buildAdjacency (which iterates a step's deploy
// artifacts map). See DESIGN-PRINCIPLES.md "Reproducibility is enforced,
// not hoped for".
func (d *DAG) Tree() string {
	var sb strings.Builder

	// Roots: sinks (steps no other step depends on), sorted for
	// deterministic output.
	roots := []primitive.Identifier{}
	for name := range d.index {
		if len(d.reverse[name]) == 0 {
			roots = append(roots, name)
		}
	}
	slices.Sort(roots)

	visited := make(map[primitive.Identifier]bool, len(d.index))
	for i, root := range roots {
		last := i == len(roots)-1
		connector := "+-- "
		if last {
			connector = "`-- "
		}
		rootStr := string(root)
		sb.WriteString(connector)
		sb.WriteString(rootStr)
		sb.WriteString("\n")
		visited[root] = true
		d.treeNode(&sb, root, "", last, visited)
	}

	return sb.String()
}

func (d *DAG) treeNode(sb *strings.Builder, node primitive.Identifier, prefix string, lastParent bool, visited map[primitive.Identifier]bool) {
	// Copy and sort the node's dependencies so the traversal order -- and
	// thus which occurrence of a shared dependency is the full one -- is
	// deterministic. Do not sort d.edges[node] in place; it is shared.
	deps := append([]primitive.Identifier(nil), d.edges[node]...)
	slices.Sort(deps)

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
		depStr := string(dep)
		if visited[dep] {
			// Already printed in full elsewhere. Emit a back-reference
			// and do not recurse, so the shared subtree is not repeated.
			sb.WriteString(childPrefix)
			sb.WriteString(connector)
			sb.WriteString(depStr)
			sb.WriteString(" (*)\n")
			continue
		}
		visited[dep] = true
		sb.WriteString(childPrefix)
		sb.WriteString(connector)
		sb.WriteString(depStr)
		sb.WriteString("\n")
		d.treeNode(sb, dep, childPrefix, last, visited)
	}
}

// PackBaseRefs returns the distinct, digest-pinned base image references of the
// pack steps in the transitive predecessor sub-tree of fromStep, sorted for
// deterministic attestation output. It mirrors State.CollectProvenance's walk
// over the dependency edges (excluding fromStep itself), reading PackSpec.Base
// for each pack step reached. These are the base images whose signed SBOMs the
// deploy step's producer-side verification considers.
func (d *DAG) PackBaseRefs(fromStep primitive.Identifier) []primitive.ImageRef {
	seen := map[primitive.ImageRef]bool{}
	var out []primitive.ImageRef
	for name := range d.predecessors(fromStep, false) {
		s := d.index[name]
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
