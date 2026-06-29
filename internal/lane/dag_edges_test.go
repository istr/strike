package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// --------------------------------------------------------------------------.
// InputEdges.
// --------------------------------------------------------------------------.

func TestBuild_InputEdgesPopulated(t *testing.T) {
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
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	edges := dag.InputEdges["b"]
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Mount != "/in" {
		t.Errorf("Mount = %q, want /in", edges[0].Mount)
	}
	if edges[0].Subpath != nil {
		t.Errorf("Subpath = %v, want nil", edges[0].Subpath)
	}
	if edges[0].FromStep == nil || string(edges[0].FromStep.ID) != "a" {
		t.Error("FromStep should point to step 'a'")
	}
	if edges[0].FromOutput == nil || edges[0].FromOutput.ID != "out" {
		t.Error("FromOutput should point to output 'out'")
	}
}

func TestBuild_UnknownInputOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")}},
			},
			{
				ID: "b", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "a", Output: "missing"}, Mount: "/in"}},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error for unknown output")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

// --------------------------------------------------------------------------.
// PackFileEdges.
// --------------------------------------------------------------------------.

func TestBuild_PackFileEdgesPopulated(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "compile", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "binary", Type: "file", Path: primitive.RelPathPtr("binary")}},
			},
			{
				ID: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: lane.OutputRef{Step: "compile", Output: "binary"}, Dest: "/app", Mode: 0o755}},
				},
				Output: "image",
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	edges := dag.PackFileEdges["pack"]
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Dest != "/app" {
		t.Errorf("Dest = %q, want /app", edges[0].Dest)
	}
	if edges[0].FromStep == nil || string(edges[0].FromStep.ID) != "compile" {
		t.Error("FromStep should point to step 'build'")
	}
	if edges[0].FromOutput == nil || edges[0].FromOutput.ID != "binary" {
		t.Error("FromOutput should point to output 'binary'")
	}
}

func TestBuild_UnknownPackFileOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "compile", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "other", Type: "file", Path: primitive.RelPathPtr("other")}},
			},
			{
				ID: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: lane.OutputRef{Step: "compile", Output: "missing"}, Dest: "/app"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error for unknown output")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

// --------------------------------------------------------------------------.
// DeployEdges.
// --------------------------------------------------------------------------.

func TestBuild_DeployEdgesPopulated(t *testing.T) {
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
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	edges := dag.DeployEdges["deploy"]
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].ArtifactName != "image" {
		t.Errorf("ArtifactName = %q, want image", edges[0].ArtifactName)
	}
	if edges[0].FromStep == nil || string(edges[0].FromStep.ID) != "pack" {
		t.Error("FromStep should point to step 'pack'")
	}
	if !edges[0].Image {
		t.Error("edge should be the step-image arm")
	}
}

func TestBuild_UnknownDeployOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "pack", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: lane.OutputRef{Step: "pack", Output: "missing"}}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error for unknown output")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

// --------------------------------------------------------------------------.
// ImageFromEdges.
// --------------------------------------------------------------------------.

func TestBuild_ImageFromEdgesPopulated(t *testing.T) {
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
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	edge, ok := dag.ImageFromEdges["run"]
	if !ok {
		t.Fatal("expected ImageFromEdge for step 'run'")
	}
	if edge.FromStep == nil || string(edge.FromStep.ID) != "pack" {
		t.Error("FromStep should point to step 'pack'")
	}
}

func TestBuild_InputRelPathPopulated(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "src", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: primitive.RelPathPtr("tree")}},
			},
			{
				ID: "consumer", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Subpath: primitive.RelPathPtr("package.json"), Mount: "/out/package.json"},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	edges := dag.InputEdges["consumer"]
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Subpath == nil || *edges[0].Subpath != "package.json" {
		t.Errorf("Subpath = %v, want package.json", edges[0].Subpath)
	}
}

func TestBuild_SubpathOnFileOutputRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "compile", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: primitive.RelPathPtr("bin")}},
			},
			{
				ID: "consumer", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "compile", Output: "bin"}, Subpath: primitive.RelPathPtr("anything"), Mount: "/in/bin"},
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error: subpath on file output")
	}
	if !strings.Contains(err.Error(), "subpath") {
		t.Errorf("error should mention 'subpath': %v", err)
	}
}

func TestBuild_SiblingSubpathsFromSameProducerAccepted(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "src", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: primitive.RelPathPtr("tree")}},
			},
			{
				ID: "consumer", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Subpath: primitive.RelPathPtr("a.json"), Mount: "/out/a.json"},
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Subpath: primitive.RelPathPtr("b.json"), Mount: "/out/b.json"},
				},
			},
		},
	}
	if _, err := lane.Build(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
