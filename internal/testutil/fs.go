package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// ReadTemp reads a file at filepath.Join(dir, name). dir must be a
// path obtained from t.TempDir() or derived from one. This is the
// package contract; the call is gosec-G304-suppressed on that basis.
func ReadTemp(t *testing.T, dir, name string) []byte {
	t.Helper()
	full := filepath.Join(dir, name)
	data, err := os.ReadFile(full) //nolint:gosec // G304: t.TempDir() root contract; see docs/CODE-STYLE.md#path-confined-io
	if err != nil {
		t.Fatalf("ReadTemp %q: %v", name, err)
	}
	return data
}

// WriteTestBinary writes content to path with mode 0o700. WriteFile
// is called with 0o600 to satisfy gosec G306; Chmod widens the mode.
func WriteTestBinary(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteTestBinary write: %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // G302: test binary needs owner-exec; 0o700 is minimum viable mode
		t.Fatalf("WriteTestBinary chmod: %v", err)
	}
}
