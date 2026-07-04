package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

func digestRef(tag string) primitive.ImageRef {
	return primitive.ImageRef(tag + "@sha256:" + strings.Repeat("a", 64))
}

func TestPackBaseRefs_CollectsSubtreeBases(t *testing.T) {
	base := digestRef("base")
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "compile", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "binary", Type: "file", Path: primitive.RelPathPtr("binary")}},
			},
			{
				ID: "pack", Args: []string{}, Env: map[string]string{},
				Pack: &lane.PackSpec{
					Base:  base,
					Files: []lane.PackFile{{From: lane.OutputRef{Step: "compile", Output: "binary"}, Dest: "/app", Mode: 0o755}},
				},
				Output: "image",
			},
			{
				ID: "deploy", Args: []string{}, Env: map[string]string{},
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
	got := dag.PackBaseRefs("deploy")
	if len(got) != 1 || got[0] != base {
		t.Fatalf("PackBaseRefs(deploy) = %v, want [%s]", got, base)
	}
	// The deploy step itself is excluded; a leaf pack with no downstream yields
	// its base only when reached as a predecessor, confirmed above.
}
