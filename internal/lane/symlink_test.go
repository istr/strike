package lane_test

import (
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestSymlinkEscapes(t *testing.T) {
	cases := []struct {
		name    string
		linkRel string
		target  string
		escapes bool
	}{
		{"sibling", "link", "real.txt", false},
		{"subdir up to root", "a/link", "../b", false},
		{"workspace contained", "node_modules/website", "../packages/hugoautogen", false},
		{"workspace severed", "website", "../packages/hugoautogen", true},
		{"escapes root", "link", "../x", true},
		{"escapes deep", "a/b/link", "../../../x", true},
		{"absolute", "link", "/etc/passwd", true},
		{"dot self", "link", ".", false},
		{"nested target", "link", "sub/file", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lane.SymlinkEscapes(c.linkRel, c.target); got != c.escapes {
				t.Errorf("SymlinkEscapes(%q, %q) = %v, want %v", c.linkRel, c.target, got, c.escapes)
			}
		})
	}
}
