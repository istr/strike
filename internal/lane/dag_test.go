package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// --------------------------------------------------------------------------.
// TestBuild -- success cases.
// --------------------------------------------------------------------------.

func TestBuild_SingleStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{Name: "build", Image: "golang", Args: []string{"go", "build"}, Env: map[string]string{}},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(dag.Order) != 1 || dag.Order[0] != "build" {
		t.Errorf("order = %v, want [build]", dag.Order)
	}
}

func TestBuild_LinearChain(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{"b"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/b"}},
			},
			{
				Name: "c", Image: "img", Args: []string{"c"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "b.out", Mount: "/in"}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "a", "b")
	assertOrder(t, dag.Order, "b", "c")
}

func TestBuild_Diamond(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{"b"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/b"}},
			},
			{
				Name: "c", Image: "img", Args: []string{"c"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/c"}},
			},
			{
				Name: "d", Image: "img", Args: []string{"d"}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{Name: "out", From: "b.out", Mount: "/in/b"},
					{Name: "out", From: "c.out", Mount: "/in/c"},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if dag.Order[0] != "a" {
		t.Errorf("first should be 'a', got %q", dag.Order[0])
	}
	assertOrder(t, dag.Order, "a", "b")
	assertOrder(t, dag.Order, "a", "c")
	assertOrder(t, dag.Order, "b", "d")
	assertOrder(t, dag.Order, "c", "d")
}

func TestBuild_FanOut(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{"b"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
			},
			{
				Name: "c", Image: "img", Args: []string{"c"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
			},
			{
				Name: "d", Image: "img", Args: []string{"d"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if dag.Order[0] != "a" {
		t.Errorf("first should be 'a', got %q", dag.Order[0])
	}
	if len(dag.Order) != 4 {
		t.Errorf("order length = %d, want 4", len(dag.Order))
	}
}

func TestBuild_ImageFromEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{"pack"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFrom: &lane.ImageFrom{Step: "pack", Output: "img"},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "pack", "run")
}

func TestBuild_PackFileEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "build", Image: "img", Args: []string{"build"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "binary", Type: "file", Path: "/out/binary"}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "build.binary", Dest: "/app", Mode: 0o755}},
				},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "build", "pack")
}

func TestBuild_DeployArtifactEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: "pack.img"}},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "pack", "deploy")
}

// --------------------------------------------------------------------------.
// TestBuild -- error cases.
// --------------------------------------------------------------------------.

func TestBuild_DuplicateStepName(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{Name: "build", Image: "img", Args: []string{}, Env: map[string]string{}},
			{Name: "build", Image: "img", Args: []string{}, Env: map[string]string{}},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "duplicate step name")
}

func TestBuild_UnknownImageFromStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "missing", Output: "img"},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_ImageFromWrongOutputType(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "build", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: "/out/bin"}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "build", Output: "bin"},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not image")
}

func TestBuild_ImageFromMissingOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{Name: "build", Image: "img", Args: []string{}, Env: map[string]string{}},
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "build", Output: "missing"},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not found")
}

func TestBuild_UnknownInputStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "run", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "missing.out", Mount: "/in"}},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_InvalidInputRef(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "run", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "noperiod", Mount: "/in"}},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "invalid reference")
}

func TestBuild_UnknownPackFileStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "missing.bin", Dest: "/app"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_PackFileMissingOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "build", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "other", Type: "file", Path: "/out/other"}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "build.missing", Dest: "/app"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not found")
}

func TestBuild_UnknownDeployArtifact(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"img": {From: "missing.out"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_Cycle(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{Name: "out", From: "b.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/b"}},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "cyclic dependency")
}

// --------------------------------------------------------------------------.
// TestTree.
// --------------------------------------------------------------------------.

func TestTree(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "out", From: "a.out", Mount: "/in"}},
			},
		},
	}
	dag, err := lane.Build(p)
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
func assertOrder(t *testing.T, order []string, before, after string) {
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

func TestBuild_ProvenancePathInOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: "/out/tree"}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "/out/provenance.json",
				},
			},
		},
	}
	if _, err := lane.Build(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_ProvenancePathOutsideOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: "/out/tree"}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "/etc/provenance.json",
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not within any declared output")
}

func TestBuild_ProvenancePathRelative(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: "/out/tree"}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "out/provenance.json",
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "must be absolute")
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
