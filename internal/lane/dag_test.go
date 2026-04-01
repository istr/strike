package lane

import "testing"

func TestIsOCITarOutput(t *testing.T) {
	dag := &DAG{
		Steps: map[string]*Step{
			"builder": {
				Name: "builder",
				Outputs: []OutputSpec{
					{Name: "binary", Type: "file", Path: "/out/strike"},
					{Name: "image", Type: "image", Path: "/out/image.tar"},
				},
			},
		},
	}

	tests := []struct {
		inp  InputRef
		want bool
	}{
		{InputRef{Name: "image", From: "builder"}, true},
		{InputRef{Name: "binary", From: "builder"}, false},
		{InputRef{Name: "missing", From: "builder"}, false},
		{InputRef{Name: "image", From: "unknown"}, false},
	}

	for _, tt := range tests {
		got := dag.IsOCITarOutput(tt.inp)
		if got != tt.want {
			t.Errorf("IsOCITarOutput(%s/%s) = %v, want %v",
				tt.inp.From, tt.inp.Name, got, tt.want)
		}
	}
}
