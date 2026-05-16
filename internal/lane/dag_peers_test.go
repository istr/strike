package lane_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
)

// httpsPeer returns a minimal valid HTTPSPeer for CollectPeers tests.
func httpsPeer(host string) lane.Peer {
	return lane.HTTPSPeer{
		Type: "https",
		Host: transport.Host(host),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
}

// minStep returns a minimal step with one file-typed output named "out".
// Caller fills in name and peers.
func minStep(name string, peers []lane.Peer) lane.Step {
	return lane.Step{
		Name:    name,
		Image:   lane.Ptr(lane.ImageRef("alpine:3.20")),
		Args:    []string{"echo", "ok"},
		Env:     map[string]string{},
		Inputs:  []lane.InputRef{},
		Secrets: []lane.SecretRef{},
		Outputs: []lane.OutputSpec{
			{Name: "out", Type: "file", Path: "/out/o"},
		},
		Peers: peers,
	}
}

func TestCollectPeers_NilDAG(t *testing.T) {
	var d *lane.DAG
	got := d.CollectPeers("anything")
	if got == nil {
		t.Fatal("CollectPeers on nil receiver returned nil; expected non-nil empty map")
	}
	if len(got) != 0 {
		t.Errorf("CollectPeers on nil receiver returned %v; want empty map", got)
	}
}

func TestCollectPeers_StepWithoutPeers(t *testing.T) {
	p := &lane.Lane{
		Name:     "t",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			minStep("a", nil),
		},
	}
	d, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := d.CollectPeers("a")
	if len(got) != 0 {
		t.Errorf("step without peers produced result %v; want empty map", got)
	}
}

func TestCollectPeers_SingleStepIncludesSelf(t *testing.T) {
	peer := httpsPeer("api.example.com")
	p := &lane.Lane{
		Name:     "t",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			minStep("a", []lane.Peer{peer}),
		},
	}
	d, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := d.CollectPeers("a")
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %v", len(got), got)
	}
	if !reflect.DeepEqual(got["a"], []lane.Peer{peer}) {
		t.Errorf("got[\"a\"] = %v, want %v", got["a"], []lane.Peer{peer})
	}
}

// TestCollectPeers_TransitivePredecessors verifies the walk follows
// all dependency edges. Lane structure: a -> b -> c. Calling
// CollectPeers("c") must return peers from a, b, and c.
func TestCollectPeers_TransitivePredecessors(t *testing.T) {
	peerA := httpsPeer("a.example")
	peerB := httpsPeer("b.example")
	peerC := httpsPeer("c.example")

	p := &lane.Lane{
		Name:     "t",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			minStep("a", []lane.Peer{peerA}),
			withInput(minStep("b", []lane.Peer{peerB}), "a", "out", "/in/a"),
			withInput(minStep("c", []lane.Peer{peerC}), "b", "out", "/in/b"),
		},
	}
	d, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := d.CollectPeers("c")

	gotKeys := keysOf(got)
	wantKeys := []string{"a", "b", "c"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("keys = %v, want %v", gotKeys, wantKeys)
	}
}

// TestCollectPeers_OnlyTransitive verifies that steps not in the
// upstream chain are excluded. Lane: a -> c, b -> c. CollectPeers("a")
// must include a but exclude b and c.
func TestCollectPeers_OnlyTransitive(t *testing.T) {
	peerA := httpsPeer("a.example")
	peerB := httpsPeer("b.example")
	peerC := httpsPeer("c.example")

	p := &lane.Lane{
		Name:     "t",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			minStep("a", []lane.Peer{peerA}),
			minStep("b", []lane.Peer{peerB}),
			withTwoInputs(minStep("c", []lane.Peer{peerC}),
				"a", "out", "/in/a",
				"b", "out", "/in/b"),
		},
	}
	d, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := d.CollectPeers("a")
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %v", len(got), got)
	}
	if _, ok := got["a"]; !ok {
		t.Errorf("missing 'a' in result: %v", got)
	}
}

// TestCollectPeers_DiamondDedup verifies that a step reachable via
// two paths is visited once. Lane: root -> {left, right} -> bottom.
// CollectPeers("bottom") must list root exactly once.
func TestCollectPeers_DiamondDedup(t *testing.T) {
	peerR := httpsPeer("root.example")
	peerL := httpsPeer("left.example")
	peerRt := httpsPeer("right.example")
	peerB := httpsPeer("bottom.example")

	p := &lane.Lane{
		Name:     "t",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			minStep("root", []lane.Peer{peerR}),
			withInput(minStep("left", []lane.Peer{peerL}), "root", "out", "/in/r"),
			withInput(minStep("right", []lane.Peer{peerRt}), "root", "out", "/in/r"),
			withTwoInputs(minStep("bottom", []lane.Peer{peerB}),
				"left", "out", "/in/l",
				"right", "out", "/in/r"),
		},
	}
	d, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := d.CollectPeers("bottom")

	gotKeys := keysOf(got)
	wantKeys := []string{"bottom", "left", "right", "root"}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("keys = %v, want %v", gotKeys, wantKeys)
	}

	if len(got["root"]) != 1 {
		t.Errorf("root visited %d times, want 1: %v", len(got["root"]), got["root"])
	}
}

// TestCollectPeers_StepsWithoutPeersOmitted verifies that intermediate
// steps without peers do not create entries in the result, even when
// they participate in the transitive walk.
func TestCollectPeers_StepsWithoutPeersOmitted(t *testing.T) {
	peerA := httpsPeer("a.example")
	peerC := httpsPeer("c.example")

	p := &lane.Lane{
		Name:     "t",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			minStep("a", []lane.Peer{peerA}),
			withInput(minStep("b", nil), "a", "out", "/in/a"),
			withInput(minStep("c", []lane.Peer{peerC}), "b", "out", "/in/b"),
		},
	}
	d, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := d.CollectPeers("c")
	if _, ok := got["b"]; ok {
		t.Errorf("step b has no peers but appears in result: %v", got)
	}
	if _, ok := got["a"]; !ok {
		t.Errorf("step a missing from result: %v", got)
	}
	if _, ok := got["c"]; !ok {
		t.Errorf("step c missing from result: %v", got)
	}
}

// Test helpers.

func withInput(s lane.Step, fromStep, fromOutput, mount string) lane.Step {
	s.Inputs = append(s.Inputs, lane.InputRef{
		From:  fromStep + "." + fromOutput,
		Mount: lane.AbsPath(mount),
	})
	return s
}

func withTwoInputs(s lane.Step, fromA, outA, mountA, fromB, outB, mountB string) lane.Step {
	s = withInput(s, fromA, outA, mountA)
	s = withInput(s, fromB, outB, mountB)
	return s
}

func keysOf(m map[string][]lane.Peer) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
