package transport_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// mustDialer constructs a Dialer for the declared resolver, failing the
// test if the declaration is rejected.
func mustDialer(t *testing.T, decl endpoint.DoT) *transport.Dialer {
	t.Helper()
	d, err := transport.NewDialer(decl)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return d
}

// testResolverADN is the name every declared test resolver is verified
// against. It is under the reserved .test TLD (RFC 6761) and is never
// resolved: the dial routes to the listener literal and uses this as the SNI
// and the reference identifier.
const testResolverADN primitive.Host = "resolver.test"

// caBundleResolver declares a DoT resolver reached at the listener address
// addr and verified against testResolverADN through the CA bundle written at
// caPath. It is the only resolver declaration shape the schema admits.
func caBundleResolver(t *testing.T, addr string, caPath primitive.AbsPath) endpoint.DoT {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("parse listener address %q: %v", addr, err)
	}
	port := primitive.Port(ap.Port())
	return endpoint.DoT{
		ADN:   testResolverADN,
		IP:    primitive.IPFromAddr(ap.Addr()),
		Port:  &port,
		Trust: endpoint.CABundle{Type: "caBundle", Path: caPath},
	}
}

func TestNewDialer_RejectsEmptyResolverADN(t *testing.T) {
	_, err := transport.NewDialer(endpoint.DoT{})
	if err == nil {
		t.Fatal("expected an error for a resolver declaration with no adn")
	}
	if !strings.Contains(err.Error(), "resolver adn") {
		t.Errorf("error %q must name the missing resolver adn", err)
	}
}

// TestNewDialer_RejectsUnusableResolverIP pins that a declaration lane
// validation would have rejected is refused when the Dialer is constructed
// rather than on every lookup: the dial target is projected once, so an
// unusable literal has nowhere later to surface.
func TestNewDialer_RejectsUnusableResolverIP(t *testing.T) {
	zero := primitive.Port(0)
	tests := []struct {
		port    *primitive.Port
		name    string
		ip      primitive.IP
		wantErr string
	}{
		{name: "ip is a name", ip: "resolver.example", wantErr: "ip"},
		{name: "ip not canonical", ip: "::0001", wantErr: "not canonical"},
		{name: "port out of range", ip: "127.0.0.1", port: &zero, wantErr: "out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transport.NewDialer(endpoint.DoT{
				ADN:  testResolverADN,
				IP:   tt.ip,
				Port: tt.port,
			})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestDialerDialPeer_ResolvesThenVerifies(t *testing.T) {
	peerCert, caPEM := testCAAndServerCert(t, "peer.example")
	peer := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*peerCert},
		MinVersion:   tls.VersionTLS13,
	})

	resolverCert, resolverCAPEM := testCAAndServerCert(t, "resolver.test")
	resolverAddr := startDNSTLSServer(t, resolverCert, aRecordHandler("peer.example.", [4]byte{127, 0, 0, 1}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	port := primitive.Port(peer.Port())
	d := mustDialer(t, caBundleResolver(t, resolverAddr, writeCABundle(t, "resolver-ca.pem", resolverCAPEM)))
	conn, err := d.DialPeer(ctx, "peer.example", port, endpoint.CABundle{
		Type: "caBundle",
		Path: writeCABundle(t, "ca.pem", caPEM),
	})
	if err != nil {
		t.Fatalf("DialPeer: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test peer conn")

	// The recorded peer is the declared identity with the dialed port, not
	// the address the resolver answered with.
	want := endpoint.Address{Host: "peer.example", Port: &port}.Authority()
	if got := conn.Identity().PeerAddress.Authority(); got != want {
		t.Errorf("PeerAddress = %q, want %q", got, want)
	}
}

func TestDialerDialPeer_RejectsOutOfRangePort(t *testing.T) {
	_, caPEM := testCAAndServerCert(t, "resolver.test")
	d := mustDialer(t, caBundleResolver(t, "127.0.0.1:853", writeCABundle(t, "unused-ca.pem", caPEM)))
	_, err := d.DialPeer(context.Background(), "peer.example", 0, endpoint.CABundle{Type: "caBundle"})
	if err == nil {
		t.Fatal("expected an error for a zero port")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error %q must report the port as out of range", err)
	}
}

func TestDialerDialPeer_LookupFailurePropagates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	_, caPEM := testCAAndServerCert(t, "resolver.test")
	d := mustDialer(t, caBundleResolver(t, "127.0.0.1:1", writeCABundle(t, "unused-ca.pem", caPEM)))
	_, err := d.DialPeer(ctx, "peer.example", 443, endpoint.CABundle{Type: "caBundle"})
	if err == nil {
		t.Fatal("expected an error when the resolver is unreachable")
	}
	if !strings.Contains(err.Error(), "lookup") {
		t.Errorf("error %q must report the failed lookup", err)
	}
}
