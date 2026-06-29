// Package primitive defines the leaf scalar vocabulary -- the shared, composable
// constraint types (paths, identifier, base64, git commit, sha256, image ref,
// artifact type, digest, duration) that the lane and attestation schemas build
// on. See docs/ADR-047-spec-package-layering.md.
package primitive

import (
	"fmt"
	"path"
	"strings"
)

// NewAbsPath returns the AbsPath form of s. It does not validate; callers that
// need a checked path use Validate. It owns the conversion in this package so
// callers do not convert at the call site.
func NewAbsPath(s string) AbsPath {
	return AbsPath(s)
}

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

// Clean returns the lexically cleaned form of the path.
func (p AbsPath) Clean() string {
	return path.Clean(string(p))
}
