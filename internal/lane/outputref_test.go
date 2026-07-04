package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestOutputRef_Ref(t *testing.T) {
	tests := []struct {
		name string
		ref  lane.OutputRef
		want string
	}{
		{"simple", lane.OutputRef{Step: "build", Output: "binary"}, "build.binary"},
		{"hyphens", lane.OutputRef{Step: "npm-install", Output: "node-modules"}, "npm-install.node-modules"},
		{"numeric", lane.OutputRef{Step: "s1", Output: "a"}, "s1.a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ref.Ref(); got != tt.want {
				t.Errorf("Ref() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOutputRef_RefRejectsDottedIdentifier pins the grammar property Ref
// depends on: #Identifier excludes '.', so the dotted "step.output" encoding
// stays unambiguous. A lane whose output-ref component carries a '.' must fail
// schema validation; if #Identifier is ever widened to admit '.', this trips,
// flagging that Ref (and the spec hashes and cache tags built on it) need
// revisiting.
func TestOutputRef_RefRejectsDottedIdentifier(t *testing.T) {
	_, _, _, err := lane.Parse(mustFilePath(t, "testdata/invalid_dotted_ref.yaml"))
	if err == nil {
		t.Fatal("expected error for output ref with a dotted identifier")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("error should mention validation: %v", err)
	}
}
