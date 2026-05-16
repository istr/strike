package executor_test

import (
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
)

func TestNetworkMode_NilIsNone(t *testing.T) {
	if got := executor.NetworkMode(nil); got != "none" {
		t.Errorf("NetworkMode(nil) = %q, want %q", got, "none")
	}
}

func TestNetworkMode_EmptyIsNone(t *testing.T) {
	if got := executor.NetworkMode([]lane.Peer{}); got != "none" {
		t.Errorf("NetworkMode([]) = %q, want %q", got, "none")
	}
}

func TestNetworkMode_NonEmptyIsBridge(t *testing.T) {
	peer := lane.HTTPSPeer{
		Type: "https",
		Host: transport.Host("example.com"),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	if got := executor.NetworkMode([]lane.Peer{peer}); got != "bridge" {
		t.Errorf("NetworkMode([peer]) = %q, want %q", got, "bridge")
	}
}
