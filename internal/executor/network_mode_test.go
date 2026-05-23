package executor_test

import (
	"testing"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
)

func TestSSHContainerPorts_NilIsNil(t *testing.T) {
	if got := executor.SSHContainerPorts(nil); got != nil {
		t.Errorf("SSHContainerPorts(nil) = %v, want nil", got)
	}
}

func TestSSHContainerPorts_NoSSHPeersIsNil(t *testing.T) {
	peers := []lane.Peer{
		lane.HTTPSPeer{
			Type: "https",
			Host: transport.Host("example.com"),
			Trust: transport.FingerprintTrust{
				Mode:        "cert_fingerprint",
				Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	if got := executor.SSHContainerPorts(peers); got != nil {
		t.Errorf("SSHContainerPorts(no SSH) = %v, want nil", got)
	}
}

func TestSSHContainerPorts_OneSSHPeer(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: "git.example.com",
			KnownHosts: []lane.KnownHostEntry{{
				KeyType: "ssh-ed25519",
				Key:     "AAAA",
			}},
		},
	}
	got := executor.SSHContainerPorts(peers)
	want := map[string]uint16{"git.example.com": capsule.SSHContainerPortBase}
	if len(got) != len(want) {
		t.Fatalf("SSHContainerPorts = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("SSHContainerPorts[%q] = %d, want %d", k, got[k], v)
		}
	}
}

func TestSSHContainerPorts_TwoSSHPeers(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: "git.example.com",
			KnownHosts: []lane.KnownHostEntry{{
				KeyType: "ssh-ed25519",
				Key:     "AAAA",
			}},
		},
		lane.SSHPeer{
			Type: "ssh",
			Host: "git2.example.com",
			KnownHosts: []lane.KnownHostEntry{{
				KeyType: "ssh-ed25519",
				Key:     "BBBB",
			}},
		},
	}
	got := executor.SSHContainerPorts(peers)
	if got["git.example.com"] != capsule.SSHContainerPortBase {
		t.Errorf("first peer port = %d, want %d", got["git.example.com"], capsule.SSHContainerPortBase)
	}
	if got["git2.example.com"] != capsule.SSHContainerPortBase+1 {
		t.Errorf("second peer port = %d, want %d", got["git2.example.com"], capsule.SSHContainerPortBase+1)
	}
}

func TestSSHContainerPorts_ExplicitPort(t *testing.T) {
	peers := []lane.Peer{
		lane.SSHPeer{
			Type: "ssh",
			Host: "git.example.com:2222",
			KnownHosts: []lane.KnownHostEntry{{
				KeyType: "ssh-ed25519",
				Key:     "AAAA",
			}},
		},
	}
	got := executor.SSHContainerPorts(peers)
	// The container port is independent of the declared upstream port.
	if got["git.example.com"] != capsule.SSHContainerPortBase {
		t.Errorf("SSHContainerPorts[git.example.com] = %d, want %d", got["git.example.com"], capsule.SSHContainerPortBase)
	}
}
