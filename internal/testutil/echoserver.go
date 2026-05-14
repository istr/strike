package testutil

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
)

// StartEchoSocket creates a Unix-domain socket that echoes any input.
// The listener is cleaned up via t.Cleanup. Returns the socket path.
func StartEchoSocket(t *testing.T) string {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "echo.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("StartEchoSocket listen: %v", err)
	}
	t.Cleanup(func() { CloseLog(t, ln, "echo listener") })
	go acceptEchoLoop(t, ln)
	return sockPath
}

func acceptEchoLoop(t *testing.T, ln net.Listener) {
	t.Helper()
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go func(c net.Conn) {
			defer CloseLog(t, c, "echo conn")
			if _, err := io.Copy(c, c); err != nil {
				t.Logf("echo copy: %v", err)
			}
		}(c)
	}
}
