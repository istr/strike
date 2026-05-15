package executor_test

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/test/crossval"
)

func TestRenderKnownHosts_nil_peers(t *testing.T) {
	if got := executor.RenderKnownHosts(nil); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
}

func TestRenderKnownHosts_empty_peers(t *testing.T) {
	if got := executor.RenderKnownHosts([]lane.Peer{}); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
}

func TestRenderKnownHosts_non_ssh_only(t *testing.T) {
	peers := []lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: "example.com", Trust: lane.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
		lane.OCIPeer{Type: "oci", Registry: "ghcr.io"},
	}
	if got := executor.RenderKnownHosts(peers); got != nil {
		t.Fatalf("got %q, want nil", got)
	}
}

func TestRenderKnownHosts_single_peer_single_key(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: "git.example.com",
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey1"},
			},
		},
	}
	want := "git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey1\n"
	got := executor.RenderKnownHosts(peers)
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRenderKnownHosts_single_peer_multiple_keys(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: "git.example.com",
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-rsa", Key: "AAAAB3Rsa"},
				{KeyType: "ecdsa-sha2-nistp256", Key: "AAAAE2VjZHNh"},
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5"},
			},
		},
	}
	want := "git.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNh\n" +
		"git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n" +
		"git.example.com ssh-rsa AAAAB3Rsa\n"
	got := executor.RenderKnownHosts(peers)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderKnownHosts_multiple_peers_sorted(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh", Host: "zeta.example",
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "ZetaKey"}},
		},
		lane.SSHPeer{
			Type: "ssh", Host: "alpha.example",
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "AlphaKey"}},
		},
		lane.SSHPeer{
			Type: "ssh", Host: "mu.example",
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "MuKey"}},
		},
	}
	want := "alpha.example ssh-ed25519 AlphaKey\n" +
		"mu.example ssh-ed25519 MuKey\n" +
		"zeta.example ssh-ed25519 ZetaKey\n"
	got := executor.RenderKnownHosts(peers)
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderKnownHosts_host_with_port(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: "git.example.com:2222",
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAIPortKey"},
			},
		},
	}
	want := "[git.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPortKey\n"
	got := executor.RenderKnownHosts(peers)
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRenderKnownHosts_mixed_peer_list(t *testing.T) {
	peers := []lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: "api.example.com", Trust: lane.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
		lane.SSHPeer{
			Type: "ssh", Host: "git.example.com",
			KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "MixedKey"}},
		},
		lane.OCIPeer{Type: "oci", Registry: "ghcr.io"},
	}
	want := "git.example.com ssh-ed25519 MixedKey\n"
	got := executor.RenderKnownHosts(peers)
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRenderKnownHosts_order_independence(t *testing.T) {
	a := lane.SSHPeer{
		Type: "ssh", Host: "alpha.example",
		KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "AlphaKey"}},
	}
	b := lane.SSHPeer{
		Type: "ssh", Host: "beta.example",
		KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "BetaKey"}},
	}
	c := lane.SSHPeer{
		Type: "ssh", Host: "gamma.example",
		KnownHosts: []lane.KnownHostEntry{{KeyType: "ssh-ed25519", Key: "GammaKey"}},
	}

	order1 := executor.RenderKnownHosts([]lane.Peer{c, a, b})
	order2 := executor.RenderKnownHosts([]lane.Peer{b, c, a})

	if string(order1) != string(order2) {
		t.Fatalf("different orders produced different output:\n  order1: %q\n  order2: %q", order1, order2)
	}
}

func TestConfigureSSHPeers_no_ssh_peers(t *testing.T) {
	dir := t.TempDir()
	mount, env, err := executor.ConfigureSSHPeers([]lane.Peer{
		lane.HTTPSPeer{Type: "https", Host: "example.com", Trust: lane.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:abc"}},
	}, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mount != nil {
		t.Errorf("mount = %v, want nil", mount)
	}
	if env != nil {
		t.Errorf("env = %v, want nil", env)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("scratch dir not empty: %v", entries)
	}
}

func TestConfigureSSHPeers_with_ssh_peers(t *testing.T) {
	dir := t.TempDir()
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh", Host: "git.example.com",
			KnownHosts: []lane.KnownHostEntry{
				{KeyType: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"},
			},
		},
	}
	mount, env, err := executor.ConfigureSSHPeers(peers, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mount == nil {
		t.Fatal("mount is nil")
	}
	if mount.Target != "/etc/ssh/ssh_known_hosts" {
		t.Errorf("mount.Target = %q, want /etc/ssh/ssh_known_hosts", mount.Target)
	}
	if !mount.ReadOnly {
		t.Error("mount.ReadOnly = false, want true")
	}

	fileBytes, err := os.ReadFile(mount.Source)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	wantBytes := executor.RenderKnownHosts(peers)
	if string(fileBytes) != string(wantBytes) {
		t.Errorf("file content mismatch:\n  got:  %q\n  want: %q", fileBytes, wantBytes)
	}

	if env == nil {
		t.Fatal("env is nil")
	}
	const wantCmd = "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts -o PasswordAuthentication=no -o BatchMode=yes"
	if env["GIT_SSH_COMMAND"] != wantCmd {
		t.Errorf("GIT_SSH_COMMAND =\n  %q\nwant:\n  %q", env["GIT_SSH_COMMAND"], wantCmd)
	}
	if len(env) != 1 {
		t.Errorf("env has %d entries, want 1", len(env))
	}
}

// Golden tests against crossval vectors.

type sshKnownHostsVectorExpected struct {
	ContentBase64 string `json:"content_base64"`
}

type sshKnownHostsVectorInputs struct {
	Peers []json.RawMessage `json:"peers"`
}

type sshKnownHostsVector struct {
	Description string                      `json:"description"`
	Boundary    string                      `json:"boundary"`
	Expected    sshKnownHostsVectorExpected `json:"expected"`
	Inputs      sshKnownHostsVectorInputs   `json:"inputs"`
}

func TestRenderKnownHosts_Golden(t *testing.T) {
	files, err := fs.Glob(crossval.FS, "sshknownhosts/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no sshknownhosts vectors found")
	}

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
			for i, raw := range vec.Inputs.Peers {
				p, pErr := lane.UnmarshalPeer(raw)
				if pErr != nil {
					t.Fatalf("unmarshal peer[%d]: %v", i, pErr)
				}
				peers[i] = p
			}

			got := executor.RenderKnownHosts(peers)
			gotB64 := base64.StdEncoding.EncodeToString(got)
			if gotB64 != vec.Expected.ContentBase64 {
				t.Errorf("content_base64 mismatch:\n  got:  %s\n  want: %s", gotB64, vec.Expected.ContentBase64)
			}
		})
	}
}
