package executor_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/testutil"
)

func startFakeAgent(t *testing.T) string {
	t.Helper()
	return testutil.StartEchoSocket(t)
}

func sshPeer(host string) lane.SSHPeer {
	return lane.SSHPeer{
		Type: "ssh",
		Host: host,
		KnownHosts: []lane.KnownHostEntry{
			{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
		},
	}
}

func TestStartAgentProxy_NoSSHPeers(t *testing.T) {
	dir := t.TempDir()
	peers := []lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: "example.com", Trust: lane.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
		lane.OCIPeer{Type: "oci", Registry: "ghcr.io"},
	}
	mount, env, err := executor.StartAgentProxy(context.Background(), peers, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mount != nil {
		t.Errorf("mount = %v, want nil", mount)
	}
	if env != nil {
		t.Errorf("env = %v, want nil", env)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Errorf("scratch dir not empty: %v", entries)
	}
}

func TestStartAgentProxy_EmptyPeers(t *testing.T) {
	dir := t.TempDir()
	for _, peers := range [][]lane.Peer{nil, {}} {
		mount, env, err := executor.StartAgentProxy(context.Background(), peers, dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mount != nil || env != nil {
			t.Errorf("expected nil mount and env for empty peers")
		}
	}
}

func TestStartAgentProxy_NoAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	peers := []lane.Peer{sshPeer("git.example.com")}
	_, _, err := executor.StartAgentProxy(context.Background(), peers, dir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	want := `ssh peer "git.example.com" declared but SSH_AUTH_SOCK not set`
	if got := err.Error(); !strings.Contains(got, want) {
		t.Errorf("error = %q, want substring %q", got, want)
	}
}

func TestStartAgentProxy_AuthSockMissing(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/nonexistent-strike-test-socket-"+t.Name())
	dir := t.TempDir()
	peers := []lane.Peer{sshPeer("git.example.com")}
	_, _, err := executor.StartAgentProxy(context.Background(), peers, dir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v, want wrapped fs.ErrNotExist", err)
	}
}

func TestStartAgentProxy_AuthSockNotSocket(t *testing.T) {
	dir := t.TempDir()
	regularFile := filepath.Join(dir, "not-a-socket")
	if writeErr := os.WriteFile(regularFile, []byte("hello"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	t.Setenv("SSH_AUTH_SOCK", regularFile)

	scratchDir := t.TempDir()
	peers := []lane.Peer{sshPeer("git.example.com")}
	_, _, err := executor.StartAgentProxy(context.Background(), peers, scratchDir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "is not a socket") {
		t.Errorf("error = %q, want substring %q", got, "is not a socket")
	}
}

func TestStartAgentProxy_ForwardsBidirectionally(t *testing.T) {
	fakeSock := startFakeAgent(t)
	t.Setenv("SSH_AUTH_SOCK", fakeSock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scratchDir := t.TempDir()
	peers := []lane.Peer{sshPeer("git.example.com")}
	mount, _, err := executor.StartAgentProxy(ctx, peers, scratchDir)
	if err != nil {
		t.Fatalf("StartAgentProxy: %v", err)
	}
	if mount == nil {
		t.Fatal("mount is nil")
	}

	var d net.Dialer
	conn, dialErr := d.DialContext(ctx, "unix", mount.Source)
	if dialErr != nil {
		t.Fatalf("dial proxy: %v", dialErr)
	}
	defer testutil.CloseLog(t, conn, "agent proxy conn")

	msg := []byte("hello-agent-proxy")
	if _, writeErr := conn.Write(msg); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}

	// Half-close write so the echo server sends back and closes.
	if uc, ok := conn.(*net.UnixConn); ok {
		if cwErr := uc.CloseWrite(); cwErr != nil {
			t.Logf("half-close write: %v", cwErr)
		}
	}

	buf, readErr := io.ReadAll(conn)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestStartAgentProxy_TerminatesOnContextCancel(t *testing.T) {
	fakeSock := startFakeAgent(t)
	t.Setenv("SSH_AUTH_SOCK", fakeSock)

	ctx, cancel := context.WithCancel(context.Background())
	scratchDir := t.TempDir()
	peers := []lane.Peer{sshPeer("git.example.com")}
	mount, _, err := executor.StartAgentProxy(ctx, peers, scratchDir)
	if err != nil {
		t.Fatalf("StartAgentProxy: %v", err)
	}

	// Verify it works before cancel.
	var d net.Dialer
	conn, dialErr := d.DialContext(ctx, "unix", mount.Source)
	if dialErr != nil {
		t.Fatalf("dial proxy: %v", dialErr)
	}
	testutil.CloseLog(t, conn, "agent proxy conn")

	cancel()

	// The context cancel triggers listener.Close() asynchronously.
	// Use a short-timeout dial loop to confirm the listener is gone.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer dialCancel()

	for {
		c, retryErr := d.DialContext(dialCtx, "unix", mount.Source)
		if retryErr != nil {
			break // listener closed, as expected
		}
		testutil.CloseLog(t, c, "agent proxy retry conn")
		if dialCtx.Err() != nil {
			t.Error("expected dial to fail after context cancel, but it kept succeeding")
			break
		}
	}
}

func TestStartAgentProxy_MountAndEnv(t *testing.T) {
	fakeSock := startFakeAgent(t)
	t.Setenv("SSH_AUTH_SOCK", fakeSock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scratchDir := t.TempDir()
	peers := []lane.Peer{sshPeer("git.example.com")}
	mount, env, err := executor.StartAgentProxy(ctx, peers, scratchDir)
	if err != nil {
		t.Fatalf("StartAgentProxy: %v", err)
	}

	if mount == nil {
		t.Fatal("mount is nil")
	}
	if mount.Target != "/run/strike/ssh-agent.sock" {
		t.Errorf("mount.Target = %q, want /run/strike/ssh-agent.sock", mount.Target)
	}
	if mount.ReadOnly {
		t.Error("mount.ReadOnly = true, want false")
	}

	if env == nil {
		t.Fatal("env is nil")
	}
	if len(env) != 1 {
		t.Errorf("env has %d entries, want 1", len(env))
	}
	if env["SSH_AUTH_SOCK"] != "/run/strike/ssh-agent.sock" {
		t.Errorf("SSH_AUTH_SOCK = %q, want /run/strike/ssh-agent.sock", env["SSH_AUTH_SOCK"])
	}
}
