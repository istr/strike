package lane

import (
	"fmt"
	"path"
	"strings"
)

// Validate checks that the ContainerPath is absolute and canonical.
// Uses path (not filepath) because container paths are always forward-slash.
func (p ContainerPath) Validate() error {
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
func (p ContainerPath) HasPrefix(dir string) bool {
	return strings.HasPrefix(string(p), dir)
}

// Dir returns the directory portion of the path.
func (p ContainerPath) Dir() string {
	return path.Dir(string(p))
}

// String returns the path as a plain string.
func (p ContainerPath) String() string {
	return string(p)
}
