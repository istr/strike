package executor_test

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// captureEngine records the RunOpts and seeds passed to ContainerRunHeld.
type captureEngine struct {
	capturedSeeds []container.Seed
	captured      container.RunOpts
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

func (e *captureEngine) ImageSave(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(io.LimitReader(nil, 0)), nil
}
func (e *captureEngine) Ping(context.Context) error          { return nil }
func (e *captureEngine) TLSIdentity() *container.TLSIdentity { return nil }
func (e *captureEngine) Identity() *container.EngineIdentity { return nil }
func (e *captureEngine) Info(context.Context) error          { return nil }
func (e *captureEngine) ContainerRunHeld(_ context.Context, opts container.RunOpts, seeds []container.Seed) (string, int, error) {
	e.captured = opts
	e.capturedSeeds = seeds
	return "test-container-id", 0, nil
}

func (e *captureEngine) ContainerArchive(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (e *captureEngine) ContainerCommit(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (e *captureEngine) ContainerRemove(_ context.Context, _ string) error             { return nil }
func (e *captureEngine) VolumeCreate(_ context.Context, _ string) error                { return nil }
func (e *captureEngine) SeedVolumes(_ context.Context, _ []container.VolumeSeed) error { return nil }
func (e *captureEngine) VolumeRemove(_ context.Context, _ string) error                { return nil }

const sshTrustVolumeDest = "/etc/ssh"

// specgenTestCapsule creates a minimal capsule for specgen tests.
// The capsule is not Start()ed; Execute only calls PastaArgs() and
// ResolverAddr(), which work without binding listeners. Returns the
// capsule and a synthetic CA volume name (the mock engine does not
// perform real volume operations).
func specgenTestCapsule(t *testing.T) (*capsule.NetworkCapsule, string) {
	t.Helper()
	ca, err := transport.New("specgen-test")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ca, "specgen CA") })

	c, err := capsule.New("specgen", capsule.HostPorts{Resolver: 15353, Mediator: 15354},
		nil, nil, 0, ca,
		func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		})
	if err != nil {
		t.Fatalf("capsule.New: %v", err)
	}
	return c, "strike-ca-specgen-test"
}

func TestExecute_WithSSHPeer(t *testing.T) {
	eng := &captureEngine{}
	caps, caPath := specgenTestCapsule(t)

	r := executor.Run{
		Engine:    eng,
		Capsule:   caps,
		CAVolume:  caPath,
		SSHVolume: "strike-ssh-test-step-12345",
		Secrets:   nil,
		Step: &lane.Step{
			ID:    "test-step",
			Image: lane.Ptr(lane.ImageRef("alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000")),
			Args:  []string{"true"},
			Peers: []lane.Peer{
				lane.SSHPeer{
					Type: "ssh",
					Host: transport.Host("git.example.com"),
					KnownHosts: []lane.KnownHostEntry{
						{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
					},
				},
			},
		},
		VolumeName: "",
	}

	if _, err := r.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Verify SSH trust volume in TrustVolumes (not bind mounts).
	var foundSSHVolume bool
	for _, v := range eng.captured.TrustVolumes {
		if v.Dest == sshTrustVolumeDest {
			foundSSHVolume = true
			if v.Name != "strike-ssh-test-step-12345" {
				t.Errorf("SSH trust volume name = %q, want strike-ssh-test-step-12345", v.Name)
			}
		}
	}
	if !foundSSHVolume {
		t.Error("expected TrustVolume with Dest=/etc/ssh")
	}

	// No bind mounts for known_hosts or ssh_config.
	for _, m := range eng.captured.Mounts {
		if m.Target == "/etc/ssh/ssh_known_hosts" {
			t.Error("unexpected known_hosts bind mount; should be delivered via trust volume")
		}
		if m.Target == "/etc/ssh/ssh_config" || m.Target == "/etc/ssh/strike_config" {
			t.Error("unexpected ssh_config bind mount; should be delivered via trust volume")
		}
	}

	// GIT_SSH_COMMAND should not contain -F (system-wide config via volume).
	if cmd, ok := eng.captured.Env["GIT_SSH_COMMAND"]; ok {
		if strings.Contains(cmd, "-F") {
			t.Errorf("GIT_SSH_COMMAND should not contain -F: %q", cmd)
		}
	}
}

func TestExecute_WithoutSSHPeer(t *testing.T) {
	eng := &captureEngine{}
	caps, caPath := specgenTestCapsule(t)

	r := executor.Run{
		Engine:   eng,
		Capsule:  caps,
		CAVolume: caPath,
		Secrets:  nil,
		Step: &lane.Step{
			ID:    "test-step",
			Image: lane.Ptr(lane.ImageRef("alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000")),
			Args:  []string{"true"},
			Peers: []lane.Peer{
				lane.HTTPSPeer{
					Type: "https",
					Host: transport.Host("api.example.com"),
					Trust: transport.FingerprintTrust{
						Type:        "certFingerprint",
						Fingerprint: "sha256:abc",
					},
				},
			},
		},
		VolumeName: "",
	}

	if _, err := r.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	for _, v := range eng.captured.TrustVolumes {
		if v.Dest == sshTrustVolumeDest {
			t.Error("unexpected SSH trust volume when no SSH peer")
		}
	}

	if _, ok := eng.captured.Env["GIT_SSH_COMMAND"]; ok {
		t.Error("unexpected GIT_SSH_COMMAND in env when no SSH peer")
	}
	if _, ok := eng.captured.Env["SSH_AUTH_SOCK"]; ok {
		t.Error("unexpected SSH_AUTH_SOCK in env when no SSH peer")
	}
}

func TestRunExecute_Seeds_PassedThrough(t *testing.T) {
	eng := &captureEngine{}
	caps, caPath := specgenTestCapsule(t)

	seedTar := bytes.NewReader([]byte("seed-content"))
	r := executor.Run{
		Engine:   eng,
		Capsule:  caps,
		CAVolume: caPath,
		Secrets:  nil,
		Step: &lane.Step{
			ID:      "consumer",
			Image:   lane.Ptr(lane.ImageRef("alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000")),
			Args:    []string{"cat", "/work/binary"},
			Workdir: lane.Ptr(lane.AbsPath("/work")),
		},
		VolumeName: "test-vol",
		Seeds: []container.Seed{
			{Tar: seedTar, Path: "/work"},
		},
	}

	if _, err := r.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(eng.capturedSeeds) != 1 {
		t.Fatalf("expected 1 seed, got %d", len(eng.capturedSeeds))
	}
	if eng.capturedSeeds[0].Path != "/work" {
		t.Errorf("seed path = %q, want /work", eng.capturedSeeds[0].Path)
	}
}
