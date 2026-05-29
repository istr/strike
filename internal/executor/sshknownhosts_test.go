package executor_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
	"github.com/istr/strike/test/crossval"
)

// testFrontKey generates an ephemeral ed25519 SSH public key for use as
// the front's synthetic host key in tests.
func testFrontKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gossh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestRenderKnownHosts_nil_peers(t *testing.T) {
	if got := executor.RenderKnownHosts(nil, testFrontKey(t)); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
}

func TestRenderKnownHosts_empty_peers(t *testing.T) {
	if got := executor.RenderKnownHosts([]lane.Peer{}, testFrontKey(t)); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
}

func TestRenderKnownHosts_non_ssh_only(t *testing.T) {
	peers := []lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: transport.Host("example.com"), Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
	}
	if got := executor.RenderKnownHosts(peers, testFrontKey(t)); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
}

func TestRenderKnownHosts_single_peer(t *testing.T) {
	fk := testFrontKey(t)
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: transport.Host("git.example.com"),
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey1"},
			},
		},
	}
	got := string(executor.RenderKnownHosts(peers, fk))
	keyLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(fk)))
	want := "git.example.com " + keyLine + "\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// The real peer key must not appear.
	if strings.Contains(got, "AAAAC3NzaC1lZDI1NTE5AAAAITestKey1") {
		t.Error("output should not contain the real peer key")
	}
}

func TestRenderKnownHosts_multiple_peers_sorted(t *testing.T) {
	fk := testFrontKey(t)
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh", Host: transport.Host("zeta.example"),
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "ZetaKey"}},
		},
		lane.SSHPeer{
			Type: "ssh", Host: transport.Host("alpha.example"),
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "AlphaKey"}},
		},
		lane.SSHPeer{
			Type: "ssh", Host: transport.Host("mu.example"),
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "MuKey"}},
		},
	}
	got := string(executor.RenderKnownHosts(peers, fk))
	keyLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(fk)))
	want := "alpha.example " + keyLine + "\n" +
		"mu.example " + keyLine + "\n" +
		"zeta.example " + keyLine + "\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderKnownHosts_host_with_port(t *testing.T) {
	fk := testFrontKey(t)
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: transport.Host("git.example.com:2222"),
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAIPortKey"},
			},
		},
	}
	got := string(executor.RenderKnownHosts(peers, fk))
	keyLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(fk)))
	want := "[git.example.com]:2222 " + keyLine + "\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRenderKnownHosts_mixed_peer_list(t *testing.T) {
	fk := testFrontKey(t)
	peers := []lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: transport.Host("api.example.com"), Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
		lane.SSHPeer{
			Type: "ssh", Host: transport.Host("git.example.com"),
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "MixedKey"}},
		},
	}
	got := string(executor.RenderKnownHosts(peers, fk))
	keyLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(fk)))
	want := "git.example.com " + keyLine + "\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRenderKnownHosts_order_independence(t *testing.T) {
	fk := testFrontKey(t)
	a := lane.SSHPeer{
		Type: "ssh", Host: transport.Host("alpha.example"),
		KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "AlphaKey"}},
	}
	b := lane.SSHPeer{
		Type: "ssh", Host: transport.Host("beta.example"),
		KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "BetaKey"}},
	}
	c := lane.SSHPeer{
		Type: "ssh", Host: transport.Host("gamma.example"),
		KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "GammaKey"}},
	}

	order1 := executor.RenderKnownHosts([]lane.Peer{c, a, b}, fk)
	order2 := executor.RenderKnownHosts([]lane.Peer{b, c, a}, fk)

	if string(order1) != string(order2) {
		t.Fatalf("different orders produced different output:\n  order1: %q\n  order2: %q", order1, order2)
	}
}

func TestSSHTrustContent_no_ssh_peers(t *testing.T) {
	kh, cfg := executor.SSHTrustContent([]lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: transport.Host("example.com"), Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
	}, nil, testFrontKey(t))
	if kh != nil {
		t.Errorf("knownHosts = %q, want nil", kh)
	}
	if cfg != nil {
		t.Errorf("sshConfig = %q, want nil", cfg)
	}
}

func testSSHHostKey(t *testing.T) (keyType, keyB64, authLine string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gossh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
	parts := strings.SplitN(line, " ", 2)
	return parts[0], parts[1], line
}

func TestSSHTrustContent_with_ssh_peers(t *testing.T) {
	_, _, authLine := testSSHHostKey(t)
	fk := testFrontKey(t)
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh", Host: transport.Host("git.example.com"),
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
			},
		},
	}

	ca, caErr := transport.New("test-lane")
	if caErr != nil {
		t.Fatalf("transport.New: %v", caErr)
	}
	t.Cleanup(func() {
		if err := ca.Close(); err != nil {
			t.Logf("ca close: %v", err)
		}
	})
	lookup := func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	hp := capsule.HostPorts{Resolver: 5353, Mediator: 5354, SSH: []uint16{5355}}
	targets := []capsule.SSHTarget{{Host: "git.example.com", HostKeys: []string{authLine}}}
	caps, capsErr := capsule.New("trust-step", hp, nil, targets, 40000, ca, lookup)
	if capsErr != nil {
		t.Fatalf("capsule.New: %v", capsErr)
	}

	kh, cfg := executor.SSHTrustContent(peers, caps, fk)

	wantKH := executor.RenderKnownHosts(peers, fk)
	if string(kh) != string(wantKH) {
		t.Errorf("knownHosts mismatch:\n  got:  %q\n  want: %q", kh, wantKH)
	}

	// The known_hosts must carry the front key, not the real peer key.
	frontKeyLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(fk)))
	if !strings.Contains(string(kh), frontKeyLine) {
		t.Errorf("known_hosts should contain front key:\n%s", kh)
	}
	if strings.Contains(string(kh), "AAAAC3NzaC1lZDI1NTE5AAAAITestKey") {
		t.Error("known_hosts should not contain the real peer key")
	}

	// The config must contain Host and SetEnv lines, no Port line.
	if !strings.Contains(string(cfg), "Host git.example.com\n") {
		t.Errorf("sshConfig missing Host line:\n%s", cfg)
	}
	if !strings.Contains(string(cfg), "SetEnv STRIKE_PEER=") {
		t.Errorf("sshConfig missing SetEnv line:\n%s", cfg)
	}
	if strings.Contains(string(cfg), "Port ") {
		t.Errorf("sshConfig should not contain a Port line:\n%s", cfg)
	}
}

func TestSSHTrustEnv_empty(t *testing.T) {
	env := executor.SSHTrustEnv()
	if len(env) != 0 {
		t.Errorf("SSHTrustEnv() = %v, want empty map", env)
	}
}

func TestSSHTrustTar_structure(t *testing.T) {
	kh := []byte("git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
	cfg := []byte("Host git.example.com\n    Port 2200\n")

	tarBytes, err := executor.SSHTrustTar(kh, cfg)
	if err != nil {
		t.Fatalf("SSHTrustTar: %v", err)
	}

	tr := tar.NewReader(bytes.NewReader(tarBytes))

	// First entry: ssh_known_hosts.
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tar entry 0: %v", err)
	}
	if hdr.Name != "ssh_known_hosts" {
		t.Errorf("entry 0 name = %q, want ssh_known_hosts", hdr.Name)
	}
	if hdr.Mode != 0o644 {
		t.Errorf("entry 0 mode = %o, want 644", hdr.Mode)
	}
	got := make([]byte, hdr.Size)
	_, err = io.ReadFull(tr, got)
	if err != nil {
		t.Fatalf("read entry 0: %v", err)
	}
	if string(got) != string(kh) {
		t.Errorf("entry 0 content = %q, want %q", got, kh)
	}

	// Second entry: ssh_config.
	hdr, err = tr.Next()
	if err != nil {
		t.Fatalf("tar entry 1: %v", err)
	}
	if hdr.Name != "ssh_config" {
		t.Errorf("entry 1 name = %q, want ssh_config", hdr.Name)
	}
	if hdr.Mode != 0o644 {
		t.Errorf("entry 1 mode = %o, want 644", hdr.Mode)
	}
	got = make([]byte, hdr.Size)
	_, err = io.ReadFull(tr, got)
	if err != nil {
		t.Fatalf("read entry 1: %v", err)
	}
	if string(got) != string(cfg) {
		t.Errorf("entry 1 content = %q, want %q", got, cfg)
	}

	// No more entries.
	_, err = tr.Next()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF after 2 entries, got %v", err)
	}
}

// Golden tests against crossval vectors. The vectors carry real peer keys,
// but RenderKnownHosts now emits the front's synthetic key. The golden test
// verifies that the correct number of hosts are emitted and that every host
// from the vector appears, each carrying the front key.

type sshKnownHostsVectorInputs struct {
	Peers []json.RawMessage `json:"peers"`
}

type sshKnownHostsVector struct {
	Description string                    `json:"description"`
	Boundary    string                    `json:"boundary"`
	Inputs      sshKnownHostsVectorInputs `json:"inputs"`
}

func TestRenderKnownHosts_Golden(t *testing.T) {
	files, err := fs.Glob(crossval.FS, "sshknownhosts/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no sshknownhosts vectors found")
	}

	fk := testFrontKey(t)
	keyLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(fk)))

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			data, err := crossval.FS.ReadFile(f)
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			var vec sshKnownHostsVector
			if err := json.Unmarshal(data, &vec); err != nil {
				t.Fatalf("unmarshal vector: %v", err)
			}

			peers := make([]lane.Peer, len(vec.Inputs.Peers))
			var sshCount int
			for i, raw := range vec.Inputs.Peers {
				p, pErr := lane.UnmarshalPeer(raw)
				if pErr != nil {
					t.Fatalf("unmarshal peer[%d]: %v", i, pErr)
				}
				peers[i] = p
				if _, ok := p.(lane.SSHPeer); ok {
					sshCount++
				}
			}

			got := executor.RenderKnownHosts(peers, fk)
			if sshCount == 0 {
				if got != nil {
					t.Errorf("expected nil for no SSH peers, got %q", got)
				}
				return
			}
			lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
			if len(lines) != sshCount {
				t.Errorf("expected %d lines, got %d: %q", sshCount, len(lines), got)
			}
			for _, line := range lines {
				if !strings.HasSuffix(line, keyLine) {
					t.Errorf("line does not end with front key: %q", line)
				}
			}
		})
	}
}
