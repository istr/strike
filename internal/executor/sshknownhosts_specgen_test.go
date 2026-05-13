package executor_test

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

// captureEngine records the RunOpts passed to ContainerRun.
type captureEngine struct {
	captured container.RunOpts
}

func (e *captureEngine) ContainerRun(_ context.Context, opts container.RunOpts) (int, error) {
	e.captured = opts
	return 0, nil
}

func (e *captureEngine) ImageExists(context.Context, string) (bool, error)    { return true, nil }
func (e *captureEngine) ImagePull(context.Context, string) error              { return nil }
func (e *captureEngine) ImagePush(context.Context, string) error              { return nil }
func (e *captureEngine) ImageLoad(context.Context, io.Reader) (string, error) { return "", nil }
func (e *captureEngine) ImageInspect(context.Context, string) (*container.ImageInfo, error) {
	return nil, nil
}
func (e *captureEngine) ImageTag(context.Context, string, string) error { return nil }
func (e *captureEngine) Ping(context.Context) error                     { return nil }
func (e *captureEngine) TLSIdentity() *container.TLSIdentity            { return nil }
func (e *captureEngine) Identity() *container.EngineIdentity            { return nil }
func (e *captureEngine) Info(context.Context) error                     { return nil }

const (
	sshKnownHostsTarget  = "/etc/ssh/ssh_known_hosts"
	containerAgentTarget = "/run/strike/ssh-agent.sock"
	wantGitSSHCommand    = "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts -o PasswordAuthentication=no -o BatchMode=yes"
)

// specgenFakeAgent creates a minimal echo socket for tests that need SSH_AUTH_SOCK.
func specgenFakeAgent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "fake-agent.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("specgenFakeAgent: %v", err)
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
	return sockPath
}

func TestExecute_WithSSHPeer(t *testing.T) {
	fakeSock := specgenFakeAgent(t)
	t.Setenv("SSH_AUTH_SOCK", fakeSock)

	eng := &captureEngine{}
	outDir := t.TempDir()

	r := executor.Run{
		Engine:  eng,
		Secrets: nil,
		Step: &lane.Step{
			Name:  "test-step",
			Image: "alpine:latest",
			Args:  []string{"true"},
			Peers: []lane.Peer{
				lane.SSHPeer{
					Type: "ssh",
					Host: "git.example.com",
					KnownHosts: []lane.KnownHostEntry{
						{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
					},
				},
			},
		},
		OutputDir: outDir,
	}

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Verify known_hosts mount
	var foundKnownHosts bool
	for _, m := range eng.captured.Mounts {
		if m.Target == sshKnownHostsTarget {
			foundKnownHosts = true
			if !m.ReadOnly {
				t.Error("ssh_known_hosts mount should be ReadOnly")
			}
		}
	}
	if !foundKnownHosts {
		t.Error("expected mount with Target=/etc/ssh/ssh_known_hosts")
	}

	// Verify GIT_SSH_COMMAND
	got, ok := eng.captured.Env["GIT_SSH_COMMAND"]
	if !ok {
		t.Fatal("expected GIT_SSH_COMMAND in env")
	}
	if got != wantGitSSHCommand {
		t.Errorf("GIT_SSH_COMMAND =\n  %q\nwant:\n  %q", got, wantGitSSHCommand)
	}
}

func TestExecute_WithoutSSHPeer(t *testing.T) {
	eng := &captureEngine{}
	outDir := t.TempDir()

	r := executor.Run{
		Engine:  eng,
		Secrets: nil,
		Step: &lane.Step{
			Name:  "test-step",
			Image: "alpine:latest",
			Args:  []string{"true"},
			Peers: []lane.Peer{
				lane.HTTPSPeer{
					Type: "https",
					Host: "api.example.com",
					Trust: lane.FingerprintTrust{
						Mode:        "cert_fingerprint",
						Fingerprint: "sha256:abc",
					},
				},
			},
		},
		OutputDir: outDir,
	}

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	for _, m := range eng.captured.Mounts {
		if m.Target == sshKnownHostsTarget {
			t.Error("unexpected ssh_known_hosts mount when no SSH peer")
		}
		if m.Target == containerAgentTarget {
			t.Error("unexpected agent mount when no SSH peer")
		}
	}

	if _, ok := eng.captured.Env["GIT_SSH_COMMAND"]; ok {
		t.Error("unexpected GIT_SSH_COMMAND in env when no SSH peer")
	}
	if _, ok := eng.captured.Env["SSH_AUTH_SOCK"]; ok {
		t.Error("unexpected SSH_AUTH_SOCK in env when no SSH peer")
	}
}

func TestRunExecute_SSHAgentProxy_SpecGenerator(t *testing.T) {
	fakeSock := specgenFakeAgent(t)
	t.Setenv("SSH_AUTH_SOCK", fakeSock)

	eng := &captureEngine{}
	outDir := t.TempDir()

	r := executor.Run{
		Engine:  eng,
		Secrets: nil,
		Step: &lane.Step{
			Name:  "test-step",
			Image: "alpine:latest",
			Args:  []string{"true"},
			Peers: []lane.Peer{
				lane.SSHPeer{
					Type: "ssh",
					Host: "git.example.com",
					KnownHosts: []lane.KnownHostEntry{
						{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
					},
				},
			},
		},
		OutputDir: outDir,
	}

	if err := r.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Verify both mounts present.
	var foundKnownHosts, foundAgent bool
	for _, m := range eng.captured.Mounts {
		switch m.Target {
		case sshKnownHostsTarget:
			foundKnownHosts = true
			if !m.ReadOnly {
				t.Error("known_hosts mount should be ReadOnly")
			}
		case containerAgentTarget:
			foundAgent = true
			if m.ReadOnly {
				t.Error("agent mount should be read-write")
			}
		}
	}
	if !foundKnownHosts {
		t.Error("missing known_hosts mount")
	}
	if !foundAgent {
		t.Error("missing agent socket mount")
	}

	// Verify GIT_SSH_COMMAND includes BatchMode=yes.
	gitCmd, ok := eng.captured.Env["GIT_SSH_COMMAND"]
	if !ok {
		t.Fatal("expected GIT_SSH_COMMAND in env")
	}
	if !strings.Contains(gitCmd, "-o BatchMode=yes") {
		t.Errorf("GIT_SSH_COMMAND missing BatchMode=yes: %q", gitCmd)
	}

	// Verify SSH_AUTH_SOCK.
	authSock, ok := eng.captured.Env["SSH_AUTH_SOCK"]
	if !ok {
		t.Fatal("expected SSH_AUTH_SOCK in env")
	}
	if authSock != containerAgentTarget {
		t.Errorf("SSH_AUTH_SOCK = %q, want %q", authSock, containerAgentTarget)
	}
}

func TestRunExecute_SSHPeer_NoAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	eng := &captureEngine{}
	outDir := t.TempDir()

	r := executor.Run{
		Engine:  eng,
		Secrets: nil,
		Step: &lane.Step{
			Name:  "test-step",
			Image: "alpine:latest",
			Args:  []string{"true"},
			Peers: []lane.Peer{
				lane.SSHPeer{
					Type: "ssh",
					Host: "git.example.com",
					KnownHosts: []lane.KnownHostEntry{
						{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
					},
				},
			},
		},
		OutputDir: outDir,
	}

	err := r.Execute(context.Background())
	if err == nil {
		t.Fatal("expected error when SSH_AUTH_SOCK not set")
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK not set") {
		t.Errorf("error = %q, want substring about SSH_AUTH_SOCK", err.Error())
	}
}
