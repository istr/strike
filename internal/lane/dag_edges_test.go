package lane_test

import (
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

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
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	if _, err := lane.Build(p, index); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
