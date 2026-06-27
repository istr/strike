package mediator_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/transport"
)

// TestMediator_CloudflareHTTPS_INTEGRATION drives a full
// end-to-end mediated TLS connection to Cloudflare's
// one.one.one.one HTTPS endpoint and verifies that an HTTP/1.1
// HEAD request receives a response.
func TestMediator_CloudflareHTTPS_INTEGRATION(t *testing.T) {
	dotFingerprint := os.Getenv("STRIKE_CLOUDFLARE_DOT_FINGERPRINT")
	httpsFingerprint := os.Getenv("STRIKE_CLOUDFLARE_HTTPS_FINGERPRINT")
	if dotFingerprint == "" || httpsFingerprint == "" {
		t.Skip("STRIKE_CLOUDFLARE_DOT_FINGERPRINT or STRIKE_CLOUDFLARE_HTTPS_FINGERPRINT not set; skipping")
	}

	dotDecl := transport.DNSResolver{
		Host: endpoint.MustParseAuthority("1.1.1.1:853"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: dotFingerprint,
		},
	}
	upstream := func(ctx context.Context, name string) ([]netip.Addr, error) {
		return transport.LookupHost(ctx, dotDecl, name)
	}

	ca, err := transport.New("integration-lane")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	defer closer.Warn(ca, "integration CA")

	peers := []mediator.PeerTrust{
		{
			Host: "one.one.one.one",
			Trust: endpoint.Fingerprint{
				Type:        "certFingerprint",
				Fingerprint: httpsFingerprint,
			},
		},
	}

	m, err := mediator.New("integration-step", peers, ca, upstream)
	if err != nil {
		t.Fatalf("mediator.New: %v", err)
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closer.Warn(listener, "integration listener")

	ctx, cancel := context.WithTimeout(context.Background(), 30*clock.Second)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- m.Serve(ctx, listener) }()

	// Build a client that trusts the ephemeral CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PublicCertPEM()) {
		t.Fatal("failed to append CA cert to pool")
	}
	clientConfig := &tls.Config{
		RootCAs:    pool,
		ServerName: "one.one.one.one",
		MinVersion: tls.VersionTLS13,
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientConn := tls.Client(raw, clientConfig)
	if hsErr := clientConn.HandshakeContext(ctx); hsErr != nil {
		closer.Warn(raw, "integration client raw")
		t.Fatalf("client handshake: %v", hsErr)
	}
	defer closer.Warn(clientConn, "integration client conn")

	if _, wErr := clientConn.Write([]byte("HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")); wErr != nil {
		t.Fatalf("write: %v", wErr)
	}
	resp, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response")
	}

	cancel()
	if sErr := <-serveErr; sErr != nil {
		t.Fatalf("Serve: %v", sErr)
	}

	records := m.Records()
	if len(records) == 0 {
		t.Fatal("expected at least one record")
	}
	if records[0].Decision != mediator.DecisionAllowed {
		t.Errorf("Decision = %q, want %q", records[0].Decision, mediator.DecisionAllowed)
	}
	if records[0].Upstream == nil {
		t.Error("Upstream identity is nil")
	}
}
