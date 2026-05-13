package integration_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
)

// TestSSHAgentSocketBindMount verifies that a bind-mounted socket at
// /run/strike/ssh-agent.sock is reachable inside a hardened container.
// This confirms the OCI runtime creates the /run/strike/ parent
// directory before the read-only rootfs switch takes effect.
func TestSSHAgentSocketBindMount(t *testing.T) {
	engine := needsEngine(t)
	ensureImage(t, engine, goImage)

	// Create a fake agent socket on the host.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "agent.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck,gosec // test cleanup
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // test echo server
				io.Copy(c, c)   //nolint:errcheck,gosec // test echo server
			}()
		}
	}()

	var stdout, stderr bytes.Buffer
	opts := deploy.HardenedRunOpts()
	opts.Image = goImage
	opts.Entrypoint = []string{"stat"}
	opts.Cmd = []string{"/run/strike/ssh-agent.sock"}
	opts.Mounts = []container.Mount{
		{Source: sockPath, Target: "/run/strike/ssh-agent.sock", ReadOnly: false},
	}
	opts.Stdout = &stdout
	opts.Stderr = &stderr

	exitCode, err := engine.ContainerRun(context.Background(), opts)
	if err != nil {
		t.Fatalf("ContainerRun: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("stat /run/strike/ssh-agent.sock failed (exit %d):\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}
	t.Logf("stat output: %s", stdout.String())
}
