//go:build integration

package resolver_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/resolver"
	"github.com/istr/strike/internal/transport"
)

// TestResolver_CloudflareDoT_INTEGRATION wires a Resolver with
// a transport.LookupHost-backed upstream pointed at Cloudflare
// DoT; queries `one.one.one.one` (always resolvable, returns
// known addresses) through the allowlist resolver; asserts the
// response contains 1.1.1.1 or 1.0.0.1.
func TestResolver_CloudflareDoT_INTEGRATION(t *testing.T) {
	fingerprint := os.Getenv("STRIKE_CLOUDFLARE_DOT_FINGERPRINT")
	if fingerprint == "" {
		t.Skip("STRIKE_CLOUDFLARE_DOT_FINGERPRINT not set; skipping")
	}
	decl := transport.DNSResolver{
		Host: "1.1.1.1:853",
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: fingerprint,
		},
	}
	upstream := func(ctx context.Context, name string) ([]netip.Addr, error) {
		return transport.LookupHost(ctx, decl, name)
	}
	r, err := resolver.New("integration-test", []transport.Host{"one.one.one.one"}, upstream)
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
			return new(net.Dialer).DialContext(dialCtx, "tcp", udp.LocalAddr().String())
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
	found := false
	for _, a := range addrs {
		if a == netip.MustParseAddr("1.1.1.1") || a == netip.MustParseAddr("1.0.0.1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 1.1.1.1 or 1.0.0.1 in resolved addresses, got %v", addrs)
	}

	records := r.Records()
	if len(records) == 0 {
		t.Fatal("expected at least one record, got 0")
	}
	if records[0].Decision != resolver.DecisionAllowed {
		t.Errorf("first record Decision = %q, want %q", records[0].Decision, resolver.DecisionAllowed)
	}
}
