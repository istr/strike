package closer_test

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/istr/strike/internal/closer"
)

func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	fn()
	log.SetOutput(os.Stderr)
	return buf.String()
}

func TestWarn_Success(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closer-test-")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	out := captureLogs(t, func() { closer.Warn(f, "test close") })
	if out != "" {
		t.Errorf("expected no log output, got %q", out)
	}
}

func TestWarn_Failure(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closer-test-")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("initial close: %v", err)
	}

	out := captureLogs(t, func() { closer.Warn(f, "already closed") })
	if !strings.Contains(out, "WARN") || !strings.Contains(out, "already closed") {
		t.Errorf("expected WARN log with context, got %q", out)
	}
}

func TestRemove_Success(t *testing.T) {
	dir := t.TempDir()
	out := captureLogs(t, func() { closer.Remove(dir, "test remove") })
	if out != "" {
		t.Errorf("expected no log output, got %q", out)
	}
}

func TestRemove_NonexistentPath(t *testing.T) {
	// os.RemoveAll on a nonexistent path returns nil.
	out := captureLogs(t, func() { closer.Remove("/nonexistent/path/for/closer/test", "missing dir") })
	if out != "" {
		t.Errorf("expected no log output for nonexistent path, got %q", out)
	}
}
