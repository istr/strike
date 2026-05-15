package lane

import (
	"fmt"
	"path"
	"strings"
)

// Validate checks that the AbsPath is absolute and canonical.
// Uses path (not filepath) because container paths are always forward-slash.
func (p AbsPath) Validate() error {
	s := string(p)
	if !path.IsAbs(s) {
		return fmt.Errorf("must be absolute")
	}
	if path.Clean(s) != s {
		return fmt.Errorf("must be canonical (cleaned: %q)", path.Clean(s))
	}
	return nil
}

// HasPrefix reports whether p starts with the given directory prefix.
func (p AbsPath) HasPrefix(dir string) bool {
	return strings.HasPrefix(string(p), dir)
}

// Dir returns the directory portion of the path.
func (p AbsPath) Dir() string {
	return path.Dir(string(p))
}

// String returns the path as a plain string.
func (p AbsPath) String() string {
	return string(p)
}
