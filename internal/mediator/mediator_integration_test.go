package mediator_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// itestPeerHost is the harness registry hostname the mediated connection
// targets. The harness DoT resolver serves an A record for it, and Caddy
// terminates TLS for it under the exported internal root.
const itestPeerHost = "registry.127.0.0.1.sslip.io"

// TestMediator_HarnessHTTPS_INTEGRATION drives a full end-to-end
// mediated TLS connection to the harness registry endpoint and
// verifies that an HTTP/1.1 HEAD request receives a response. Both
// hops are anchored on checked-out harness material: the DoT
// resolver on pki/resolver.crt, the mediated peer on the exported
// pki/caddy-root.crt. The peer name is resolved by the harness
// resolver itself, so the mediated hop performs no external DNS.
//
// The harness is a prerequisite: the test runs by default and
// fails fast when it is down; set STRIKE_INTEGRATION=0 to skip.
func TestMediator_HarnessHTTPS_INTEGRATION(t *testing.T) {
	engine := testutil.RequireEngine(t)
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	resolverCert := primitive.AbsPath(filepath.Join(harness, "pki", "resolver.crt"))
	caddyRoot := primitive.AbsPath(filepath.Join(harness, "pki", "caddy-root.crt"))

	dialer, err := transport.NewDialer(endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("127.0.0.1:8853"),
		Trust: endpoint.CABundle{
			Type: "caBundle",
			Path: resolverCert,
		},
	})
	if err != nil {
		t.Fatalf("transport.NewDialer: %v", err)
	}

	ca, err := transport.New("integration-lane")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	defer closer.Warn(ca, "integration CA")

	peers := []mediator.PeerTrust{
		{
			Address: endpoint.MustParseAuthority(itestPeerHost + ":5443"),
			Trust: endpoint.CABundle{
				Type: "caBundle",
				Path: caddyRoot,
			},
		},
	}

	m, err := mediator.New("integration-step", peers, ca, dialer)
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
		ServerName: itestPeerHost,
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

	if _, wErr := clientConn.Write([]byte("HEAD /v2/ HTTP/1.1\r\nHost: " + itestPeerHost + "\r\nConnection: close\r\n\r\n")); wErr != nil {
		closer.Warn(clientConn, "integration client conn")
		t.Fatalf("write: %v", wErr)
	}
	resp, err := io.ReadAll(clientConn)
	closer.Warn(clientConn, "integration client conn")
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
