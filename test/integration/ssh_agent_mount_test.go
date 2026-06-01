package integration_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/testutil"
)

// TestSSHAgentSocketBindMount verifies that a bind-mounted socket at
// /run/strike/ssh-agent.sock is reachable inside a hardened container.
// This confirms the OCI runtime creates the /run/strike/ parent
// directory before the read-only rootfs switch takes effect.
func TestSSHAgentSocketBindMount(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ensureImage(t, engine, goImage)

	// Create a fake agent socket on the host.
	sockPath := testutil.StartEchoSocket(t)

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
