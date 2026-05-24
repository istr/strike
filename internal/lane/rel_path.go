package lane

import (
	"fmt"
	"path"
	"strings"
)

// Validate checks that the RelPath is relative and canonical.
// Uses path (not filepath) because container paths are always forward-slash.
func (p RelPath) Validate() error {
	s := string(p)
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if path.IsAbs(s) {
		return fmt.Errorf("must be relative")
	}
	if path.Clean(s) != s {
		return fmt.Errorf("must be canonical (cleaned: %q)", path.Clean(s))
	}
	// Reject traversal: leading or embedded ".." segments.
	if s == ".." || strings.HasPrefix(s, "../") || strings.Contains(s, "/../") || strings.HasSuffix(s, "/..") {
		return fmt.Errorf("must not contain path traversal (..)")
	}
	return nil
}

// HasPrefix reports whether p starts with the given directory prefix.
func (p RelPath) HasPrefix(dir string) bool {
	return strings.HasPrefix(string(p), dir)
}

// Dir returns the directory portion of the path.
func (p RelPath) Dir() string {
	return path.Dir(string(p))
}

// String returns the path as a plain string.
func (p RelPath) String() string {
	return string(p)
}
