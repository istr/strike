package lane_test

import (
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestIsOCITarOutput(t *testing.T) {
	dag := &lane.DAG{
		Steps: map[string]*lane.Step{
			"builder": {
				Name: "builder",
				Outputs: []lane.OutputSpec{
					{Name: "binary", Type: "file", Path: "/out/strike"},
					{Name: "image", Type: "image", Path: "/out/image.tar"},
				},
			},
		},
	}

	tests := []struct {
		inp  lane.InputRef
		want bool
	}{
		{lane.InputRef{Name: "image", From: "builder"}, true},
		{lane.InputRef{Name: "binary", From: "builder"}, false},
		{lane.InputRef{Name: "missing", From: "builder"}, false},
		{lane.InputRef{Name: "image", From: "unknown"}, false},
	}

	for _, tt := range tests {
		got := dag.IsOCITarOutput(tt.inp)
		if got != tt.want {
			t.Errorf("IsOCITarOutput(%s/%s) = %v, want %v",
				tt.inp.From, tt.inp.Name, got, tt.want)
		}
	}
}
