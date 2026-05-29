package closer_test

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
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

type permErrCloser struct{}

func (permErrCloser) Close() error { return os.ErrPermission }

func TestWarn_Failure(t *testing.T) {
	out := captureLogs(t, func() { closer.Warn(permErrCloser{}, "perm denied") })
	if !strings.Contains(out, "WARN") || !strings.Contains(out, "perm denied") {
		t.Errorf("expected WARN log with context, got %q", out)
	}
}

func TestWarn_ExpectedClose_Silent(t *testing.T) {
	// A closer returning io.EOF (expected shutdown) should not log.
	eofCloser := closerFunc(func() error { return io.EOF })
	out := captureLogs(t, func() { closer.Warn(eofCloser, "eof close") })
	if out != "" {
		t.Errorf("expected no log for expected close, got %q", out)
	}

	// A pre-closed net.Pipe end returns an expected close error.
	_, right := net.Pipe()
	if err := right.Close(); err != nil {
		t.Fatalf("close right: %v", err)
	}
	out = captureLogs(t, func() { closer.Warn(right, "closed pipe") })
	if out != "" {
		t.Errorf("expected no log for closed pipe, got %q", out)
	}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestIsExpectedClose(t *testing.T) {
	tests := []struct {
		err  error
		name string
		want bool
	}{
		{name: "EOF", err: io.EOF, want: true},
		{name: "net.ErrClosed", err: net.ErrClosed, want: true},
		{name: "os.ErrClosed", err: os.ErrClosed, want: true},
		{name: "closed network conn", err: errors.New("use of closed network connection"), want: true},
		{name: "broken pipe", err: errors.New("broken pipe"), want: true},
		{name: "connection reset", err: errors.New("connection reset by peer"), want: true},
		{name: "permission denied", err: os.ErrPermission, want: false},
		{name: "plain error", err: errors.New("nope"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := closer.IsExpectedClose(tt.err); got != tt.want {
				t.Errorf("IsExpectedClose(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
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
