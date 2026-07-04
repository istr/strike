package lane_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// --------------------------------------------------------------------------.
// TestBuild -- success cases.
// --------------------------------------------------------------------------.

func TestBuild_SingleStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{ID: "build", Image: primitive.ImageRefPtr("golang"), Args: []string{"go", "build"}, Env: map[string]string{}},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	if len(dag.Order()) != 1 || dag.Order()[0] != "build" {
		t.Errorf("order = %v, want [build]", dag.Order())
	}
}

func TestBuild_LinearChain(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: primitive.ImageRefPtr("img"), Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "b", Image: primitive.ImageRefPtr("img"), Args: []string{"b"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("b")}},
			},
			{
				ID: "c", Image: primitive.ImageRefPtr("img"), Args: []string{"c"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "b", Output: "out"}, Mount: "/in"}},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order(), "a", "b")
	assertOrder(t, dag.Order(), "b", "c")
}

func TestBuild_Diamond(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: primitive.ImageRefPtr("img"), Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "b", Image: primitive.ImageRefPtr("img"), Args: []string{"b"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("b")}},
			},
			{
				ID: "c", Image: primitive.ImageRefPtr("img"), Args: []string{"c"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("c")}},
			},
			{
				ID: "d", Image: primitive.ImageRefPtr("img"), Args: []string{"d"}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "b", Output: "out"}, Mount: "/in/b"},
					{From: lane.OutputRef{Step: "c", Output: "out"}, Mount: "/in/c"},
				},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	if dag.Order()[0] != "a" {
		t.Errorf("first should be 'a', got %q", dag.Order()[0])
	}
	assertOrder(t, dag.Order(), "a", "b")
	assertOrder(t, dag.Order(), "a", "c")
	assertOrder(t, dag.Order(), "b", "d")
	assertOrder(t, dag.Order(), "c", "d")
}

func TestBuild_FanOut(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: primitive.ImageRefPtr("img"), Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "b", Image: primitive.ImageRefPtr("img"), Args: []string{"b"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
			},
			{
				ID: "c", Image: primitive.ImageRefPtr("img"), Args: []string{"c"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
			},
			{
				ID: "d", Image: primitive.ImageRefPtr("img"), Args: []string{"d"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	if dag.Order()[0] != "a" {
		t.Errorf("first should be 'a', got %q", dag.Order()[0])
	}
	if len(dag.Order()) != 4 {
		t.Errorf("order length = %d, want 4", len(dag.Order()))
	}
}

func TestBuild_ImageFromEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "pack", Image: primitive.ImageRefPtr("img"), Args: []string{"pack"}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFromStep: primitive.IdentifierPtr("pack"),
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order(), "pack", "run")
}

func TestBuild_PackFileEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "build", Image: primitive.ImageRefPtr("img"), Args: []string{"build"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "binary", Type: "file", Path: primitive.RelPathPtr("binary")}},
			},
			{
				ID: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: lane.OutputRef{Step: "build", Output: "binary"}, Dest: "/app", Mode: 0o755}},
				},
				Output: "image",
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order(), "build", "pack")
}

func TestBuild_DeployArtifactEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "pack", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: lane.StepImageRef{Step: "pack"}}},
				},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order(), "pack", "deploy")
}

// --------------------------------------------------------------------------.
// TestBuild -- error cases.
// --------------------------------------------------------------------------.

func TestIndexSteps_DuplicateStepID(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{ID: "build", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{}},
			{ID: "build", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{}},
		},
	}
	_, err := lane.IndexSteps(p)
	assertErrContains(t, err, "duplicate step name")
}

func TestBuild_Cycle(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "b", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "b", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("b")}},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	_, err = lane.Build(p, index)
	assertErrContains(t, err, "cyclic dependency")
}

// --------------------------------------------------------------------------.
// TestTree.
// --------------------------------------------------------------------------.

func TestTree(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "b", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "out"}, Mount: "/in"}},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	tree := dag.Tree()
	if !strings.Contains(tree, "a") || !strings.Contains(tree, "b") {
		t.Errorf("tree should contain 'a' and 'b', got:\n%s", tree)
	}
}

// --------------------------------------------------------------------------.
// helpers.
// --------------------------------------------------------------------------.

// assertOrder verifies that 'before' appears before 'after' in the order slice.
func assertOrder(t *testing.T, order []primitive.Identifier, before, after primitive.Identifier) {
	t.Helper()
	bi, ai := -1, -1
	for i, s := range order {
		if s == before {
			bi = i
		}
		if s == after {
			ai = i
		}
	}
	if bi == -1 {
		t.Fatalf("%q not found in order %v", before, order)
	}
	if ai == -1 {
		t.Fatalf("%q not found in order %v", after, order)
	}
	if bi >= ai {
		t.Errorf("%q (idx %d) should come before %q (idx %d) in %v", before, bi, after, ai, order)
	}
}

// --------------------------------------------------------------------------.
// Provenance path validation.
// --------------------------------------------------------------------------.

// --------------------------------------------------------------------------.
// Deterministic order.
// --------------------------------------------------------------------------.

// TestBuild_DeterministicOrder asserts that lane.Build
// produces a byte-identical dag.Order() across many invocations
// of the same input. With three independent root steps and
// Go's non-deterministic map iteration, a naive Kahn
// implementation would produce different orderings on
// different runs.
func TestBuild_DeterministicOrder(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "zebra", Image: primitive.ImageRefPtr("img"),
				Args: []string{"z"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("z")}},
			},
			{
				ID: "alpha", Image: primitive.ImageRefPtr("img"),
				Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "middle", Image: primitive.ImageRefPtr("img"),
				Args: []string{"m"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("m")}},
			},
		},
	}

	want := []primitive.Identifier{"alpha", "middle", "zebra"}
	for i := range 100 {
		index, err := lane.IndexSteps(p)
		if err != nil {
			t.Fatalf("lane.IndexSteps: %v", err)
		}
		dag, err := lane.Build(p, index)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if !reflect.DeepEqual(dag.Order(), want) {
			t.Fatalf("iteration %d: Order = %v, want %v "+
				"(alphabetic among independent roots)",
				i, dag.Order(), want)
		}
	}
}

// TestBuild_DeterministicOrder_Diamond asserts the property
// holds for a non-trivial graph where multiple valid
// topological orderings exist: root -> {left, right} -> bottom.
func TestBuild_DeterministicOrder_Diamond(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "root", Image: primitive.ImageRefPtr("img"),
				Args: []string{"r"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("r")}},
			},
			{
				ID: "right", Image: primitive.ImageRefPtr("img"),
				Args: []string{"rt"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "root", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("rt")}},
			},
			{
				ID: "left", Image: primitive.ImageRefPtr("img"),
				Args: []string{"l"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "root", Output: "out"}, Mount: "/in"}},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("l")}},
			},
			{
				ID: "bottom", Image: primitive.ImageRefPtr("img"),
				Args: []string{"b"}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "left", Output: "out"}, Mount: "/in/l"},
					{From: lane.OutputRef{Step: "right", Output: "out"}, Mount: "/in/r"},
				},
			},
		},
	}

	// root first; left before right (alphabetic); bottom last.
	want := []primitive.Identifier{"root", "left", "right", "bottom"}
	for i := range 100 {
		index, err := lane.IndexSteps(p)
		if err != nil {
			t.Fatalf("lane.IndexSteps: %v", err)
		}
		dag, err := lane.Build(p, index)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if !reflect.DeepEqual(dag.Order(), want) {
			t.Fatalf("iteration %d: Order = %v, want %v", i, dag.Order(), want)
		}
	}
}

// TestBuild_DeterministicOrder_LexSmallestNotFIFO pins the
// specific algorithmic contract: strike's kahnSort produces
// the lexicographically smallest valid topological order, not
// merely some deterministic order.
//
// On the graph below, two deterministic algorithms could
// legitimately produce different orders:
//
//   - "FIFO Kahn with sorted-at-insertion dependents":
//     [A, B, P, R, Q, S]. After processing A, P and R enter
//     the queue; after processing B, Q and S enter. The FIFO
//     does not interleave the two waves.
//   - "Lex-smallest Kahn (ready set sorted at extraction)":
//     [A, B, P, Q, R, S]. After both roots are processed, the
//     ready set is {P, Q, R, S}; the next extraction picks P
//     because it sorts first overall.
//
// Strike commits to the second behaviour for cross-
// implementation clarity. A future refactor that silently
// switches to FIFO semantics would fail this test, surfacing
// the spec drift before it could leak into attestation.
func TestBuild_DeterministicOrder_LexSmallestNotFIFO(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "A", Image: primitive.ImageRefPtr("img"),
				Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "B", Image: primitive.ImageRefPtr("img"),
				Args: []string{"b"}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("b")}},
			},
			{
				ID: "P", Image: primitive.ImageRefPtr("img"),
				Args: []string{"p"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "A", Output: "out"}, Mount: "/in"}},
			},
			{
				ID: "R", Image: primitive.ImageRefPtr("img"),
				Args: []string{"r"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "A", Output: "out"}, Mount: "/in"}},
			},
			{
				ID: "Q", Image: primitive.ImageRefPtr("img"),
				Args: []string{"q"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "B", Output: "out"}, Mount: "/in"}},
			},
			{
				ID: "S", Image: primitive.ImageRefPtr("img"),
				Args: []string{"s"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "B", Output: "out"}, Mount: "/in"}},
			},
		},
	}

	want := []primitive.Identifier{"A", "B", "P", "Q", "R", "S"}
	for i := range 100 {
		index, err := lane.IndexSteps(p)
		if err != nil {
			t.Fatalf("lane.IndexSteps: %v", err)
		}
		dag, err := lane.Build(p, index)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if !reflect.DeepEqual(dag.Order(), want) {
			t.Fatalf("iteration %d: Order = %v, want %v "+
				"(lex-smallest valid topology, not FIFO Kahn -- "+
				"see test doc comment for the algorithmic contract)",
				i, dag.Order(), want)
		}
	}
}

// TestTree_DeduplicatesRepeatedDependency asserts that a step which
// references one producer through several inputs depends on it once:
// the dependency-graph annotation must not list the producer twice.
func TestTree_DeduplicatesRepeatedDependency(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "producer", Image: primitive.ImageRefPtr("img"),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "directory", Path: primitive.RelPathPtr("o")}},
			},
			{
				ID: "consumer", Image: primitive.ImageRefPtr("img"),
				Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "producer", Output: "out"}, Subpath: primitive.RelPathPtr("a"), Mount: "/a"},
					{From: lane.OutputRef{Step: "producer", Output: "out"}, Subpath: primitive.RelPathPtr("b"), Mount: "/b"},
				},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	tree := dag.Tree()
	// consumer depends on producer exactly once, so producer appears as a
	// single child with no back-reference. A non-deduplicated edge would
	// print producer twice (one full occurrence, one "(*)").
	if got := strings.Count(tree, "producer"); got != 1 {
		t.Errorf("producer printed %d times, want 1 (edge not deduplicated?); got:\n%s", got, tree)
	}
	if got := strings.Count(tree, "consumer"); got != 1 {
		t.Errorf("consumer printed %d times, want 1; got:\n%s", got, tree)
	}
}

// TestTree_DiamondRendersSharedNodeOnce asserts that a node reachable
// through two paths is printed in full once and as a back-reference
// "(*)" once, never as two full subtrees.
func TestTree_DiamondRendersSharedNodeOnce(t *testing.T) {
	dir := func(name string, inputs ...lane.InputRef) lane.Step {
		return lane.Step{
			ID: primitive.Identifier(name), Image: primitive.ImageRefPtr("img"),
			Args: []string{}, Env: map[string]string{}, Inputs: inputs,
			Outputs: []lane.FileOutput{{ID: "out", Type: "directory", Path: primitive.RelPathPtr("o")}},
		}
	}
	p := &lane.Lane{
		Steps: []lane.Step{
			dir("root"),
			dir("left", lane.InputRef{From: lane.OutputRef{Step: "root", Output: "out"}, Mount: "/r"}),
			dir("right", lane.InputRef{From: lane.OutputRef{Step: "root", Output: "out"}, Mount: "/r"}),
			dir("bottom",
				lane.InputRef{From: lane.OutputRef{Step: "left", Output: "out"}, Mount: "/l"},
				lane.InputRef{From: lane.OutputRef{Step: "right", Output: "out"}, Mount: "/ri"}),
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	tree := dag.Tree()
	// Rooted at the sink (bottom). root is depended on by both left and
	// right, so it is printed in full once and as a back-reference once;
	// bottom is the sole root and appears exactly once.
	if got := strings.Count(tree, "bottom"); got != 1 {
		t.Errorf("bottom (the sink/root) appears %d times, want 1; got:\n%s", got, tree)
	}
	if got := strings.Count(tree, "root"); got != 2 {
		t.Errorf("root appears %d times, want 2 (one full, one back-ref); got:\n%s", got, tree)
	}
	if got := strings.Count(tree, "(*)"); got != 1 {
		t.Errorf("expected exactly one back-reference marker, got %d; tree:\n%s", got, tree)
	}
}

// assertErrContains checks that err is non-nil and contains substr.
func assertErrContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Errorf("error %q should contain %q", err.Error(), substr)
	}
}

// --------------------------------------------------------------------------.
// ValidateLeavesAreDeploys (ADR-039 D5).
// --------------------------------------------------------------------------.

// TestValidateLeavesAreDeploys_Valid: pack is consumed by deploy, so the
// only leaf is the deploy step -- the policy passes.
func TestValidateLeavesAreDeploys_Valid(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "pack", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: lane.StepImageRef{Step: "pack"}}},
				},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	if err := dag.ValidateLeavesAreDeploys(p); err != nil {
		t.Errorf("expected valid lane to pass, got: %v", err)
	}
}

// TestValidateLeavesAreDeploys_DeployOnly: a single deploy step is itself
// the only leaf and is a deploy -- the policy passes.
func TestValidateLeavesAreDeploys_DeployOnly(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{Artifacts: map[string]lane.ArtifactRef{}},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatal(err)
	}
	if err := dag.ValidateLeavesAreDeploys(p); err != nil {
		t.Errorf("expected deploy-only lane to pass, got: %v", err)
	}
}

// TestValidateLeavesAreDeploys_DanglingLeafRejected: "orphan" produces an
// output nothing consumes and is not a deploy, so it is a non-deploy leaf.
// Build accepts the lane (the policy is the separate gate); the policy
// rejects it, naming the offending step.
func TestValidateLeavesAreDeploys_DanglingLeafRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "pack", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: lane.StepImageRef{Step: "pack"}}},
				},
			},
			{
				ID: "orphan", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("out")}},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatalf("Build should accept the lane (policy is separate): %v", err)
	}
	assertErrContains(t, dag.ValidateLeavesAreDeploys(p), "orphan")
}
