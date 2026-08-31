package transport_test

import (
	"context"
	"crypto/tls"
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
func mustDialer(t *testing.T, decl endpoint.TLS) *transport.Dialer {
	t.Helper()
	d, err := transport.NewDialer(decl)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return d
}

// fingerprintResolver declares a DoT resolver at addr pinned to fingerprint.
func fingerprintResolver(addr string, fingerprint primitive.Digest) endpoint.TLS {
	return endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority(addr),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: fingerprint,
		},
	}
}

func TestNewDialer_RejectsEmptyResolverHost(t *testing.T) {
	_, err := transport.NewDialer(endpoint.TLS{Type: "https"})
	if err == nil {
		t.Fatal("expected an error for a resolver declaration with no host")
	}
	if !strings.Contains(err.Error(), "resolver host") {
		t.Errorf("error %q must name the missing resolver host", err)
	}
}

// TestDialer_RejectsUndialableResolver pins that a resolver declaration
// which lane validation would have rejected is refused at the dial rather
// than resolved by some other route: a name has no resolver of its own to
// resolve it, and a declaration without a port has nothing to connect to.
func TestDialer_RejectsUndialableResolver(t *testing.T) {
	tests := []struct {
		name     string
		resolver string
		wantErr  string
	}{
		{name: "host is a name", resolver: "resolver.example:853", wantErr: "not an address literal"},
		{name: "no declared port", resolver: "127.0.0.1", wantErr: "port in 1..65535 is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
			defer cancel()
			d := mustDialer(t, fingerprintResolver(tt.resolver, primitive.DigestFromHex(strings.Repeat("0", 64))))
			_, err := d.LookupHost(ctx, "peer.example")
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

	resolverCert, resolverFP := testCertPair(t, "127.0.0.1")
	resolverAddr := startDNSTLSServer(t, resolverCert, aRecordHandler("peer.example.", [4]byte{127, 0, 0, 1}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	port := primitive.Port(peer.Port())
	d := mustDialer(t, fingerprintResolver(resolverAddr, resolverFP))
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
	d := mustDialer(t, fingerprintResolver("127.0.0.1:853", primitive.DigestFromHex(strings.Repeat("0", 64))))
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
	d := mustDialer(t, fingerprintResolver("127.0.0.1:1", primitive.DigestFromHex(strings.Repeat("0", 64))))
	_, err := d.DialPeer(ctx, "peer.example", 443, endpoint.CABundle{Type: "caBundle"})
	if err == nil {
		t.Fatal("expected an error when the resolver is unreachable")
	}
	if !strings.Contains(err.Error(), "lookup") {
		t.Errorf("error %q must report the failed lookup", err)
	}
}
