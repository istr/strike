package lane

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// FilePath is a validated host-path for a lane input file. Construction
// enforces existence, regularity, and a canonical absolute form. Read
// is the single project-wide G304 chokepoint for external paths; see
// docs/CODE-STYLE.md#path-confined-io.
type FilePath struct{ s string }

// NewFilePath validates that s is a regular file at a canonical
// absolute path.
func NewFilePath(s string) (FilePath, error) {
	if s == "" {
		return FilePath{}, fmt.Errorf("lane file path is empty")
	}
	abs, err := filepath.Abs(s)
	if err != nil {
		return FilePath{}, fmt.Errorf("resolve %q: %w", s, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return FilePath{}, fmt.Errorf("stat %q: %w", abs, err)
	}
	if !info.Mode().IsRegular() {
		return FilePath{}, fmt.Errorf("not a regular file: %q", abs)
	}
	return FilePath{s: abs}, nil
}

// String returns the validated absolute path.
func (p FilePath) String() string { return p.s }

// Read returns the file contents.
func (p FilePath) Read() ([]byte, error) {
	if p.s == "" {
		return nil, fs.ErrInvalid
	}
	return os.ReadFile(p.s)
}
