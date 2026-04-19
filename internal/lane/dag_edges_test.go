package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// --------------------------------------------------------------------------.
// InputEdges.
// --------------------------------------------------------------------------.

func TestBuild_InputEdgesPopulated(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "in_a", From: "a.out", Mount: "/in"}},
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
	if edges[0].LocalName != "in_a" {
		t.Errorf("LocalName = %q, want in_a", edges[0].LocalName)
	}
	if edges[0].FromStep == nil || string(edges[0].FromStep.Name) != "a" {
		t.Error("FromStep should point to step 'a'")
	}
	if edges[0].FromOutput == nil || edges[0].FromOutput.Name != "out" {
		t.Error("FromOutput should point to output 'out'")
	}
}

func TestBuild_UnknownInputOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: "/out/a"}},
			},
			{
				Name: "b", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "in", From: "a.missing", Mount: "/in"}},
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
				Name: "compile", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "binary", Type: "file", Path: "/out/binary"}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "compile.binary", Dest: "/app", Mode: 0o755}},
				},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
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
	if edges[0].FromStep == nil || string(edges[0].FromStep.Name) != "compile" {
		t.Error("FromStep should point to step 'build'")
	}
	if edges[0].FromOutput == nil || edges[0].FromOutput.Name != "binary" {
		t.Error("FromOutput should point to output 'binary'")
	}
}

func TestBuild_UnknownPackFileOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "compile", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "other", Type: "file", Path: "/out/other"}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "compile.missing", Dest: "/app"}},
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
	edges := dag.DeployEdges["deploy"]
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].ArtifactName != "image" {
		t.Errorf("ArtifactName = %q, want image", edges[0].ArtifactName)
	}
	if edges[0].FromStep == nil || string(edges[0].FromStep.Name) != "pack" {
		t.Error("FromStep should point to step 'pack'")
	}
	if edges[0].FromOutput == nil || edges[0].FromOutput.Name != "img" {
		t.Error("FromOutput should point to output 'img'")
	}
}

func TestBuild_UnknownDeployOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: "pack.missing"}},
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
	edge, ok := dag.ImageFromEdges["run"]
	if !ok {
		t.Fatal("expected ImageFromEdge for step 'run'")
	}
	if edge.FromStep == nil || string(edge.FromStep.Name) != "pack" {
		t.Error("FromStep should point to step 'pack'")
	}
	if edge.FromOutput == nil || edge.FromOutput.Name != "img" {
		t.Error("FromOutput should point to output 'img'")
	}
}

func TestBuild_UnknownImageFromOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "pack", Output: "missing"},
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
