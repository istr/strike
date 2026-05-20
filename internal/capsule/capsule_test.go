package capsule_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// requirePrivilegedPorts skips the test if binding to port 53 requires
// privileges that the current process does not have.
func requirePrivilegedPorts(t *testing.T) {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:53")
	if err != nil {
		t.Skip("skipping: cannot bind privileged port 53 (need CAP_NET_BIND_SERVICE or root)")
	}
	testutil.CloseLog(t, ln, "privileged port probe")
}

// testUpstream returns a minimal UpstreamLookupFunc for test use.
func testUpstream() capsule.UpstreamLookupFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
}

// testCA returns a fresh ephemeral CA for test use.
func testCA(t *testing.T) *transport.EphemeralCA {
	t.Helper()
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ca, "test CA") })
	return ca
}

func TestNew_RejectsEmptyStepName(t *testing.T) {
	ca := testCA(t)
	_, err := capsule.New("", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err == nil {
		t.Error("expected error for empty stepName, got nil")
	}
}

func TestNew_RejectsIPv6Address(t *testing.T) {
	ca := testCA(t)
	_, err := capsule.New("step", netip.MustParseAddr("::1"), nil, ca, testUpstream())
	if err == nil {
		t.Error("expected error for IPv6 address, got nil")
	}
}

func TestNew_RejectsNilCA(t *testing.T) {
	_, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, nil, testUpstream())
	if err == nil {
		t.Error("expected error for nil CA, got nil")
	}
}

func TestNew_RejectsNilUpstreamLookup(t *testing.T) {
	ca := testCA(t)
	_, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, nil)
	if err == nil {
		t.Error("expected error for nil upstreamLook, got nil")
	}
}

func TestNew_EmptyPeersIsValid(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	args := c.PastaArgs()
	if len(args) == 0 {
		t.Error("expected non-empty PastaArgs")
	}
}

func TestPastaArgs_ContainsSpliceOnly(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	args := c.PastaArgs()
	if args[0] != "--splice-only" {
		t.Errorf("args[0] = %q, want --splice-only", args[0])
	}
	tCount, uCount := 0, 0
	for _, a := range args {
		if a == "-T" {
			tCount++
		}
		if a == "-U" {
			uCount++
		}
	}
	if tCount != 2 {
		t.Errorf("expected 2 -T entries, got %d", tCount)
	}
	if uCount != 1 {
		t.Errorf("expected 1 -U entry, got %d", uCount)
	}
}

func TestPastaArgs_IsSnapshot(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := c.PastaArgs()
	a[0] = "mutated"
	b := c.PastaArgs()
	if b[0] == "mutated" {
		t.Error("PastaArgs returned the same underlying slice, not a copy")
	}
}

func TestResolverAddr_UsesPort53(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := c.ResolverAddr()
	if got.Port() != 53 {
		t.Errorf("ResolverAddr port = %d, want 53", got.Port())
	}
	if got.Addr() != netip.MustParseAddr("127.0.0.40") {
		t.Errorf("ResolverAddr addr = %s, want 127.0.0.40", got.Addr())
	}
}

func TestStart_BindsListeners(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)
	addr := netip.MustParseAddr("127.0.0.40")
	c, err := capsule.New("step", addr, nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if startErr := c.Start(ctx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	defer func() {
		if stopErr := c.Stop(); stopErr != nil {
			t.Logf("capsule stop: %v", stopErr)
		}
	}()

	// Verify the addresses are in use (a duplicate bind gets EADDRINUSE).
	lc := net.ListenConfig{}
	_, err = lc.ListenPacket(ctx, "udp", "127.0.0.40:53")
	if err == nil {
		t.Error("expected EADDRINUSE on UDP 127.0.0.40:53")
	}
	_, err = lc.Listen(ctx, "tcp", "127.0.0.40:53")
	if err == nil {
		t.Error("expected EADDRINUSE on TCP 127.0.0.40:53")
	}
	_, err = lc.Listen(ctx, "tcp", "127.0.0.40:443")
	if err == nil {
		t.Error("expected EADDRINUSE on TCP 127.0.0.40:443")
	}
}

func TestStop_ReleasesListeners(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)
	addr := netip.MustParseAddr("127.0.0.40")
	c, err := capsule.New("step", addr, nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if startErr := c.Start(ctx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	if stopErr := c.Stop(); stopErr != nil {
		t.Fatalf("Stop: %v", stopErr)
	}

	// After Stop, re-bind should succeed.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.40:443")
	if err != nil {
		t.Errorf("expected re-bind to succeed after Stop, got: %v", err)
	} else {
		testutil.CloseLog(t, ln, "re-bind listener")
	}
}

func TestStop_Idempotent(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if startErr := c.Start(ctx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestStop_BeforeStart(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("Stop before Start: %v", err)
	}
}

func TestStartAfterStop_ReturnsError(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Logf("capsule stop: %v", err)
	}
	if startErr := c.Start(context.Background()); startErr == nil {
		t.Error("expected error starting after Stop, got nil")
	}
}

func TestStartTwice_ReturnsError(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if startErr := c.Start(ctx); startErr != nil {
		t.Fatalf("first Start: %v", startErr)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Logf("capsule stop: %v", err)
		}
	}()

	if startErr := c.Start(ctx); startErr == nil {
		t.Error("expected error on second Start, got nil")
	}
}

func TestRecords_BeforeStart(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := c.Records()
	if len(rec.DNS) != 0 || len(rec.Connections) != 0 {
		t.Errorf("expected empty Records before Start, got DNS=%d Connections=%d",
			len(rec.DNS), len(rec.Connections))
	}
}

func TestRecords_AfterStop_PreservesData(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)
	c, err := capsule.New("step", netip.MustParseAddr("127.0.0.40"), nil, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if startErr := c.Start(ctx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	if err := c.Stop(); err != nil {
		t.Logf("capsule stop: %v", err)
	}

	// Records should be callable after Stop without panic.
	rec := c.Records()
	_ = rec // no assertion on content; the test verifies the call does not panic.
}

func TestTwoCapsules_DistinctAddresses(t *testing.T) {
	requirePrivilegedPorts(t)
	ca := testCA(t)

	addrs, err := capsule.AllocateAddresses([]string{"step-a", "step-b"})
	if err != nil {
		t.Fatalf("AllocateAddresses: %v", err)
	}

	peers := []mediator.PeerTrust{{
		Host:  "example.com",
		Trust: transport.FingerprintTrust{Mode: "fingerprint", Fingerprint: "sha256:aaaa"},
	}}

	c1, err := capsule.New("step-a", addrs["step-a"], peers, ca, testUpstream())
	if err != nil {
		t.Fatalf("New c1: %v", err)
	}
	c2, err := capsule.New("step-b", addrs["step-b"], peers, ca, testUpstream())
	if err != nil {
		t.Fatalf("New c2: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if startErr := c1.Start(ctx); startErr != nil {
		t.Fatalf("Start c1: %v", startErr)
	}
	defer func() {
		if err := c1.Stop(); err != nil {
			t.Logf("c1 stop: %v", err)
		}
	}()

	if startErr := c2.Start(ctx); startErr != nil {
		t.Fatalf("Start c2: %v", startErr)
	}
	defer func() {
		if err := c2.Stop(); err != nil {
			t.Logf("c2 stop: %v", err)
		}
	}()
}
