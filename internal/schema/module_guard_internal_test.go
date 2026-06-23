package schema

import (
	"os"
	"testing"
)

// TestModuleFileMatchesRepo guards the inlined moduleFile constant against
// drift from the real cue.mod/module.cue, which it cannot embed directly.
func TestModuleFileMatchesRepo(t *testing.T) {
	repo, err := os.ReadFile("../../cue.mod/module.cue")
	if err != nil {
		t.Fatalf("read repo module file: %v", err)
	}
	if string(repo) != moduleFile {
		t.Fatalf("moduleFile constant has drifted from cue.mod/module.cue:\n got: %q\nwant: %q", moduleFile, string(repo))
	}
}
