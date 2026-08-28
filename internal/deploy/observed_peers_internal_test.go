package deploy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// observedPeersLane builds a two-step lane -- a build step carrying peers and
// a deploy step -- and returns the built DAG, its step index and a runtime.
// The deploy method is irrelevant here: collectObservedPeers reads recorded
// connections and declared peers, never the method.
func observedPeersLane(t *testing.T, peers []lane.Peer) (*lane.DAG, map[primitive.Identifier]*lane.Step, *lane.Runtime) {
	t.Helper()
	p := &lane.Lane{
		Name: "test-observed",
		Steps: []lane.Step{
			{
				ID:      "build",
				Image:   primitive.ImageRefPtr("alpine:3.20"),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Output:  "image",
				Peers:   peers,
			},
			{
				ID: "deploy-prod",
				Deploy: &lane.DeploySpec{
					Method:    DeployRegistryForTest(),
					Artifacts: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
					Recording: lane.StateRecording{},
				},
			},
		},
	}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return dag, index, lane.NewRuntime(dag)
}

func TestCollectObservedPeers(t *testing.T) {
	tlsFP := primitive.DigestFromHex(strings.Repeat("b", 64))
	sshFP := primitive.DigestFromHex(strings.Repeat("c", 64))

	tlsPeer := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("api.example.com:443"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: primitive.DigestFromHex(strings.Repeat("a", 64)),
		},
	}
	sshPeer := endpoint.SSH{
		Type:    "ssh",
		Address: endpoint.MustParseAuthority("git.example.com"),
		KnownHosts: []endpoint.HostKey{{
			KeyType: "ssh-ed25519",
			Key:     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		}},
	}

	dag, index, state := observedPeersLane(t, []lane.Peer{tlsPeer, sshPeer})
	state.RecordNetwork("build", capsule.Records{
		Connections: []mediator.ConnectionRecord{{
			Decision: mediator.DecisionAllowed,
			SNI:      "api.example.com",
			Upstream: &transport.ConnectionIdentity{
				LeafFingerprint: tlsFP,
				PeerAddress:     endpoint.MustParseAuthority("api.example.com:443"),
			},
			Resolved: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		}},
		SSH: []capsule.SSHConnectionRecord{{
			Decision:           mediator.DecisionAllowed,
			Host:               "git.example.com",
			Port:               22,
			HostKeyFingerprint: sshFP,
			HostKeyAlgo:        "ssh-ed25519",
			Resolved:           []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		}},
	})

	step := index["deploy-prod"]
	d := &Deployer{DAG: dag, StepID: "deploy-prod"}
	observed, attribution, err := d.collectObservedPeers(step, dag.CollectPeers(step.ID), state)
	if err != nil {
		t.Fatalf("collectObservedPeers: %v", err)
	}
	if len(observed) != 2 {
		t.Fatalf("observed peer count = %d, want 2", len(observed))
	}

	tlsObs, ok := observed["api.example.com:443"]
	if !ok {
		t.Fatal("missing observed peer api.example.com:443")
	}
	tlsID, ok := tlsObs.Identity.(ObservedTLS)
	if !ok {
		t.Fatalf("identity type = %T, want ObservedTLS", tlsObs.Identity)
	}
	if tlsID.ServerCertFingerprint != tlsFP {
		t.Errorf("TLS fingerprint = %q, want %q", tlsID.ServerCertFingerprint, tlsFP)
	}
	if len(tlsObs.Resolved) == 0 {
		t.Error("Resolved is empty for the TLS peer")
	}

	sshObs, ok := observed["git.example.com:22"]
	if !ok {
		t.Fatal("missing observed peer git.example.com:22")
	}
	sshID, ok := sshObs.Identity.(ObservedSSH)
	if !ok {
		t.Fatalf("identity type = %T, want ObservedSSH", sshObs.Identity)
	}
	if sshID.HostKeyFingerprint != sshFP {
		t.Errorf("SSH fingerprint = %q, want %q", sshID.HostKeyFingerprint, sshFP)
	}
	if sshID.HostKeyAlgo != "ssh-ed25519" {
		t.Errorf("SSH algo = %q, want ssh-ed25519", sshID.HostKeyAlgo)
	}

	buildAttr, ok := attribution["build"]
	if !ok {
		t.Fatal("missing peer attribution for build")
	}
	if len(buildAttr) != 2 {
		t.Fatalf("build attribution count = %d, want 2", len(buildAttr))
	}
}

// TestCollectObservedPeers_HonorsSSHPort asserts the SSH record's own port
// reaches the observed key, rather than a default.
func TestCollectObservedPeers_HonorsSSHPort(t *testing.T) {
	sshFP := primitive.DigestFromHex(strings.Repeat("c", 64))
	sshPeer := endpoint.SSH{
		Type:    "ssh",
		Address: endpoint.MustParseAuthority("git.example.com:2222"),
		KnownHosts: []endpoint.HostKey{{
			KeyType: "ssh-ed25519",
			Key:     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		}},
	}

	dag, index, state := observedPeersLane(t, []lane.Peer{sshPeer})
	state.RecordNetwork("build", capsule.Records{
		SSH: []capsule.SSHConnectionRecord{{
			Decision:           mediator.DecisionAllowed,
			Host:               "git.example.com",
			Port:               2222,
			HostKeyFingerprint: sshFP,
			HostKeyAlgo:        "ssh-ed25519",
			Resolved:           []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		}},
	})

	step := index["deploy-prod"]
	d := &Deployer{DAG: dag, StepID: "deploy-prod"}
	observed, _, err := d.collectObservedPeers(step, dag.CollectPeers(step.ID), state)
	if err != nil {
		t.Fatalf("collectObservedPeers: %v", err)
	}
	if _, ok := observed["git.example.com:2222"]; !ok {
		t.Fatalf("observed keys = %v, want git.example.com:2222", observed)
	}
}

// TestCollectObservedPeers_ConflictAborts asserts that the same endpoint
// observed with two different validated identities is a conflict, not a
// silent merge: the deploy is not attested.
func TestCollectObservedPeers_ConflictAborts(t *testing.T) {
	tlsPeer := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("api.example.com:443"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: primitive.DigestFromHex(strings.Repeat("a", 64)),
		},
	}
	dag, index, state := observedPeersLane(t, []lane.Peer{tlsPeer})

	conflicting := func(fp string) mediator.ConnectionRecord {
		return mediator.ConnectionRecord{
			Decision: mediator.DecisionAllowed,
			SNI:      "api.example.com",
			Upstream: &transport.ConnectionIdentity{
				LeafFingerprint: primitive.DigestFromHex(strings.Repeat(fp, 64)),
				PeerAddress:     endpoint.MustParseAuthority("api.example.com:443"),
			},
			Resolved: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		}
	}
	state.RecordNetwork("build", capsule.Records{
		Connections: []mediator.ConnectionRecord{conflicting("b"), conflicting("d")},
	})

	step := index["deploy-prod"]
	d := &Deployer{DAG: dag, StepID: "deploy-prod"}
	_, _, err := d.collectObservedPeers(step, dag.CollectPeers(step.ID), state)
	if err == nil {
		t.Fatal("collectObservedPeers: expected a conflict error, got nil")
	}
	if !strings.Contains(err.Error(), "conflicting validated identities") {
		t.Errorf("error = %q, want it to name conflicting validated identities", err.Error())
	}
}
