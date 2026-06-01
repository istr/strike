package resolver_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/resolver"
	"github.com/istr/strike/internal/transport"
)

// TestResolver_Synthesis_INTEGRATION verifies that the resolver
// synthesizes the step address for an allowlisted name. This is
// the integration-level equivalent of the unit test: it uses real
// listeners and a real net.Resolver client, but does not contact
// any upstream (the resolver is a pure allowlist gate).
func TestResolver_Synthesis_INTEGRATION(t *testing.T) {
	synthAddr := netip.MustParseAddr("127.64.0.1")
	r, err := resolver.New("integration-test", []transport.Host{"one.one.one.one"}, synthAddr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var lc net.ListenConfig
	udp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closer.Warn(udp, "integration udp")
	tcp, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closer.Warn(tcp, "integration tcp")
	ctx, cancel := context.WithTimeout(context.Background(), 15*clock.Second)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- r.Serve(ctx, udp, tcp) }()

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(dialCtx, "tcp", tcp.Addr().String())
		},
	}
	addrs, err := res.LookupNetIP(ctx, "ip4", "one.one.one.one")
	if err != nil {
		t.Fatalf("LookupNetIP: %v", err)
	}
	cancel()
	if sErr := <-serveErr; sErr != nil {
		t.Fatalf("Serve: %v", sErr)
	}

	if len(addrs) != 1 || addrs[0] != synthAddr {
		t.Errorf("expected [%s], got %v", synthAddr, addrs)
	}

	records := r.Records()
	if len(records) == 0 {
		t.Fatal("expected at least one record, got 0")
	}
	if records[0].Decision != resolver.DecisionAllowed {
		t.Errorf("first record Decision = %q, want %q", records[0].Decision, resolver.DecisionAllowed)
	}
}
