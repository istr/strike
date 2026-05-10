package executor_test

import (
	"context"
	"io"
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
	sshKnownHostsTarget = "/etc/ssh/ssh_known_hosts"
	wantGitSSHCommand   = "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts -o PasswordAuthentication=no"
)

func TestExecute_WithSSHPeer(t *testing.T) {
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

	// Verify mount
	var foundMount bool
	for _, m := range eng.captured.Mounts {
		if m.Target == sshKnownHostsTarget {
			foundMount = true
			if !m.ReadOnly {
				t.Error("ssh_known_hosts mount should be ReadOnly")
			}
		}
	}
	if !foundMount {
		t.Error("expected mount with Target=/etc/ssh/ssh_known_hosts")
	}

	// Verify env
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
	}

	if _, ok := eng.captured.Env["GIT_SSH_COMMAND"]; ok {
		t.Error("unexpected GIT_SSH_COMMAND in env when no SSH peer")
	}
}
