package copier_test

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/istr/strike/internal/copier"
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

func TestForward_NetPipe(t *testing.T) {
	src, dst := net.Pipe()

	payload := []byte("hello forward")
	go func() {
		if _, err := src.Write(payload); err != nil {
			return
		}
		if err := src.Close(); err != nil {
			return
		}
	}()

	var received bytes.Buffer
	out := captureLogs(t, func() { copier.Forward(&received, dst, "pipe test") })
	if err := dst.Close(); err != nil {
		t.Logf("dst close: %v", err)
	}

	if !bytes.Equal(received.Bytes(), payload) {
		t.Errorf("got %q, want %q", received.Bytes(), payload)
	}
	if out != "" {
		t.Errorf("unexpected log output: %q", out)
	}
}

func TestForward_ClosedSource_NoWarn(t *testing.T) {
	src, dst := net.Pipe()
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}

	var received bytes.Buffer
	out := captureLogs(t, func() { copier.Forward(&received, dst, "closed source") })
	if err := dst.Close(); err != nil {
		t.Logf("dst close: %v", err)
	}

	if out != "" {
		t.Errorf("expected no log for closed source, got %q", out)
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) {
	return 0, net.ErrClosed
}

func TestForward_WriteError_ExpectedClose(t *testing.T) {
	src, dst := net.Pipe()
	go func() {
		if _, err := src.Write([]byte("data")); err != nil {
			return
		}
		if err := src.Close(); err != nil {
			return
		}
	}()

	out := captureLogs(t, func() { copier.Forward(errWriter{}, dst, "write error") })
	if err := dst.Close(); err != nil {
		t.Logf("dst close: %v", err)
	}

	// net.ErrClosed is an expected close -- no WARN.
	if out != "" {
		t.Errorf("expected no log for expected close, got %q", out)
	}
}

type realErrWriter struct{}

func (realErrWriter) Write([]byte) (int, error) {
	return 0, os.ErrPermission
}

func TestForward_WriteError_Logged(t *testing.T) {
	src, dst := net.Pipe()
	go func() {
		if _, err := src.Write([]byte("data")); err != nil {
			return
		}
		if err := src.Close(); err != nil {
			return
		}
	}()

	out := captureLogs(t, func() { copier.Forward(realErrWriter{}, dst, "real error") })
	if err := dst.Close(); err != nil {
		t.Logf("dst close: %v", err)
	}

	if !strings.Contains(out, "WARN") || !strings.Contains(out, "real error") {
		t.Errorf("expected WARN log, got %q", out)
	}
}
