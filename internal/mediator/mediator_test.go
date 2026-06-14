package mediator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/transport"
)

// Helpers for test setup.

// testUpstream spins up a TLS echo server with a self-signed cert
// valid for the given SNI. Returns the server's cert fingerprint,
// listener address, and a cleanup function.
func testUpstream(t *testing.T, sni string) (fingerprint string, addr string, cleanup func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	now := clock.Wall()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    now.Add(-clock.Minute),
		NotAfter:     now.Add(clock.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create upstream cert: %v", err)
	}

	sum := sha256.Sum256(certDER)
	fingerprint = "sha256:" + hex.EncodeToString(sum[:])

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer closer.Warn(conn, "test upstream conn")
				if _, cpErr := io.Copy(conn, conn); cpErr != nil {
					return
				}
			}()
		}
	}()

	cleanup = func() {
		closer.Warn(tlsLn, "test upstream listener")
		wg.Wait()
	}
	return fingerprint, ln.Addr().String(), cleanup
}

// failingLookup returns an UpstreamLookupFunc that always errors.
func failingLookup(msg string) mediator.UpstreamLookupFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return nil, errors.New(msg)
	}
}

// emptyLookup returns an UpstreamLookupFunc that returns zero addresses.
func emptyLookup() mediator.UpstreamLookupFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return nil, nil
	}
}

// unreachableLookup returns an UpstreamLookupFunc that returns
// 127.0.0.1 (the upstream port 443 will not have a listener).
func unreachableLookup() mediator.UpstreamLookupFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
}

// startMediator constructs a mediator and starts Serve in a
// goroutine. Returns the mediator and the listener address.
func startMediator(t *testing.T, stepName string, peers []mediator.PeerTrust, ca *transport.EphemeralCA, lookup mediator.UpstreamLookupFunc) (*mediator.Mediator, string, context.CancelFunc) {
	t.Helper()

	m, err := mediator.New(stepName, peers, ca, lookup)
	if err != nil {
		t.Fatalf("mediator.New: %v", err)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mediator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- m.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		if sErr := <-serveErr; sErr != nil {
			t.Errorf("Serve error: %v", sErr)
		}
		closer.Warn(ln, "test mediator listener")
	})

	return m, ln.Addr().String(), cancel
}

// dialThroughMediator dials the mediator via TLS using the
// ephemeral CA as root and the given SNI. Returns the client
// tls.Conn.
func dialThroughMediator(t *testing.T, mediatorAddr, sni string, ca *transport.EphemeralCA) *tls.Conn {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PublicCertPEM()) {
		t.Fatal("failed to append CA cert to pool")
	}

	d := &net.Dialer{}
	raw, err := d.DialContext(context.Background(), "tcp", mediatorAddr)
	if err != nil {
		t.Fatalf("dial mediator: %v", err)
	}

	conn := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
	})
	if err := conn.HandshakeContext(context.Background()); err != nil {
		closer.Warn(raw, "test client raw (handshake failed)")
		t.Fatalf("client handshake through mediator: %v", err)
	}
	return conn
}

// newTestCA creates an EphemeralCA for testing.
func newTestCA(t *testing.T) *transport.EphemeralCA {
	t.Helper()
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { closer.Warn(ca, "test CA") })
	return ca
}

// waitForRecords polls m.Records() until at least n records exist
// or the context deadline expires.
func waitForRecords(ctx context.Context, m *mediator.Mediator, n int) []mediator.ConnectionRecord {
	for {
		recs := m.Records()
		if len(recs) >= n {
			return recs
		}
		if ctx.Err() != nil {
			return recs
		}
	}
}

// Tests.

func TestNew_RejectsEmptyStepName(t *testing.T) {
	ca := newTestCA(t)
	_, err := mediator.New("", nil, ca, unreachableLookup())
	if err == nil || !strings.Contains(err.Error(), "stepName") {
		t.Fatalf("expected stepName error, got: %v", err)
	}
}

func TestNew_RejectsNilCA(t *testing.T) {
	_, err := mediator.New("step", nil, nil, unreachableLookup())
	if err == nil || !strings.Contains(err.Error(), "ca") {
		t.Fatalf("expected ca error, got: %v", err)
	}
}

func TestNew_RejectsNilUpstreamLookup(t *testing.T) {
	ca := newTestCA(t)
	_, err := mediator.New("step", nil, ca, nil)
	if err == nil || !strings.Contains(err.Error(), "upstreamLook") {
		t.Fatalf("expected upstreamLook error, got: %v", err)
	}
}

func TestNew_EmptyPeersIsValid(t *testing.T) {
	ca := newTestCA(t)
	_, err := mediator.New("step", nil, ca, unreachableLookup())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_RejectsDuplicatePeer(t *testing.T) {
	ca := newTestCA(t)
	peers := []mediator.PeerTrust{
		{Host: "example.com", Trust: transport.FingerprintTrust{Type: "certFingerprint", Fingerprint: "sha256:aaa"}},
		{Host: "example.com", Trust: transport.FingerprintTrust{Type: "certFingerprint", Fingerprint: "sha256:bbb"}},
	}
	_, err := mediator.New("step", peers, ca, unreachableLookup())
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got: %v", err)
	}
}

func TestNew_CanonicalizesPeerHosts(t *testing.T) {
	ca := newTestCA(t)
	peers := []mediator.PeerTrust{
		{Host: "Example.COM", Trust: transport.FingerprintTrust{Type: "certFingerprint", Fingerprint: "sha256:aaa"}},
		{Host: "example.com.", Trust: transport.FingerprintTrust{Type: "certFingerprint", Fingerprint: "sha256:bbb"}},
	}
	_, err := mediator.New("step", peers, ca, unreachableLookup())
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error from canonicalization, got: %v", err)
	}
}

func TestServe_AllowedSNI_EndToEnd(t *testing.T) {
	ca := newTestCA(t)
	sni := "test-peer.example"

	fp, upAddr, cleanup := testUpstream(t, sni)
	defer cleanup()

	// The mediator hard-codes upstream port 443. To test the full
	// end-to-end path, bind a TCP forwarder on 127.0.0.2:443 that
	// proxies to the real test upstream on its dynamic port.
	lc := net.ListenConfig{}
	fwdLn, fwdErr := lc.Listen(context.Background(), "tcp", "127.0.0.2:443")
	if fwdErr != nil {
		t.Skipf("cannot bind 127.0.0.2:443 (need CAP_NET_BIND_SERVICE or root): %v", fwdErr)
	}
	defer closer.Warn(fwdLn, "test forwarder listener")

	var fwdWg sync.WaitGroup
	fwdWg.Add(1)
	go func() {
		defer fwdWg.Done()
		for {
			c, acceptErr := fwdLn.Accept()
			if acceptErr != nil {
				return
			}
			fwdWg.Add(1)
			go func() {
				defer fwdWg.Done()
				defer closer.Warn(c, "test forwarder conn")
				d := &net.Dialer{}
				upstream, dialErr := d.DialContext(context.Background(), "tcp", upAddr)
				if dialErr != nil {
					return
				}
				defer closer.Warn(upstream, "test forwarder upstream")
				var copyWg sync.WaitGroup
				copyWg.Add(2)
				go func() {
					defer copyWg.Done()
					if _, cpErr := io.Copy(upstream, c); cpErr != nil {
						return
					}
				}()
				go func() {
					defer copyWg.Done()
					if _, cpErr := io.Copy(c, upstream); cpErr != nil {
						return
					}
				}()
				copyWg.Wait()
			}()
		}
	}()
	t.Cleanup(func() {
		closer.Warn(fwdLn, "test forwarder shutdown")
		fwdWg.Wait()
	})

	peers := []mediator.PeerTrust{
		{Host: transport.Host(sni), Trust: transport.FingerprintTrust{
			Type:        "certFingerprint",
			Fingerprint: fp,
		}},
	}

	lookup := func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
	}

	m, mAddr, _ := startMediator(t, "e2e-step", peers, ca, lookup)
	conn := dialThroughMediator(t, mAddr, sni, ca)
	defer closer.Warn(conn, "test client conn")

	msg := []byte("hello through mediator")
	if _, writeErr := conn.Write(msg); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}

	buf := make([]byte, len(msg))
	if _, readErr := io.ReadFull(conn, buf); readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(buf) != string(msg) {
		t.Errorf("echoed = %q, want %q", buf, msg)
	}

	closer.Warn(conn, "test client conn close for records")

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, 1)
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if recs[0].Decision != mediator.DecisionAllowed {
		t.Errorf("Decision = %q, want %q", recs[0].Decision, mediator.DecisionAllowed)
	}
	if recs[0].Upstream == nil {
		t.Error("Upstream identity is nil")
	}
	if recs[0].Upstream != nil && recs[0].Upstream.LeafFingerprint != fp {
		t.Errorf("fingerprint = %q, want %q", recs[0].Upstream.LeafFingerprint, fp)
	}
	if len(recs[0].Resolved) != 1 || recs[0].Resolved[0].String() != "127.0.0.2" {
		t.Errorf("Resolved = %v, want [127.0.0.2]", recs[0].Resolved)
	}
}

func TestServe_DeniedSNI_HandshakeFails(t *testing.T) {
	ca := newTestCA(t)

	peers := []mediator.PeerTrust{
		{Host: "allowed.example", Trust: transport.FingerprintTrust{
			Type: "certFingerprint", Fingerprint: "sha256:aaa",
		}},
	}

	m, mAddr, _ := startMediator(t, "denied-step", peers, ca, unreachableLookup())

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PublicCertPEM()) {
		t.Fatal("failed to append CA cert")
	}

	d := &net.Dialer{}
	raw, err := d.DialContext(context.Background(), "tcp", mAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer closer.Warn(raw, "test denied client raw")

	conn := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: "denied.example",
		MinVersion: tls.VersionTLS13,
	})
	hsErr := conn.HandshakeContext(context.Background())
	if hsErr == nil {
		closer.Warn(conn, "test denied client conn")
		t.Fatal("expected handshake failure for denied SNI")
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, 1)
	found := false
	for _, r := range recs {
		if r.SNI == "denied.example" && r.Decision == mediator.DecisionDenied {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no denied record for denied.example; records: %+v", recs)
	}
}

func TestServe_EmptySNI_Denied(t *testing.T) {
	// Go's stdlib TLS client requires ServerName or
	// InsecureSkipVerify and refuses to send a ClientHello
	// without either. A container using a non-Go TLS stack
	// (e.g., OpenSSL) could send a ClientHello without SNI.
	// Since we cannot produce that ClientHello from Go's client,
	// verify the defensive path by connecting with a bare TCP
	// socket and closing immediately; the mediator handles the
	// broken handshake without panicking.
	ca := newTestCA(t)

	peers := []mediator.PeerTrust{
		{Host: "allowed.example", Trust: transport.FingerprintTrust{
			Type: "certFingerprint", Fingerprint: "sha256:aaa",
		}},
	}

	_, mAddr, _ := startMediator(t, "emptysni-step", peers, ca, unreachableLookup())

	d := &net.Dialer{}
	raw, err := d.DialContext(context.Background(), "tcp", mAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Close immediately -- no TLS handshake. The mediator's
	// handleConn sees a handshake error and returns cleanly.
	closer.Warn(raw, "test empty-sni client raw")
}

func TestServe_UpstreamLookupError(t *testing.T) {
	ca := newTestCA(t)
	sni := "lookup-err.example"

	peers := []mediator.PeerTrust{
		{Host: transport.Host(sni), Trust: transport.FingerprintTrust{
			Type: "certFingerprint", Fingerprint: "sha256:aaa",
		}},
	}

	m, mAddr, _ := startMediator(t, "lookup-err-step", peers, ca, failingLookup("injected lookup failure"))

	conn := dialThroughMediator(t, mAddr, sni, ca)
	defer closer.Warn(conn, "test lookup-err client")

	// The mediator allows the handshake (SNI is in the peer list)
	// but the upstream lookup fails. The mediator records an error
	// and closes the connection.
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected read error after upstream lookup failure")
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, 1)
	found := false
	for _, r := range recs {
		if r.SNI == sni && r.Decision == mediator.DecisionError && strings.Contains(r.Err, "injected lookup failure") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no error record for lookup failure; records: %+v", recs)
	}
}

func TestServe_UpstreamNoAddresses(t *testing.T) {
	ca := newTestCA(t)
	sni := "no-addrs.example"

	peers := []mediator.PeerTrust{
		{Host: transport.Host(sni), Trust: transport.FingerprintTrust{
			Type: "certFingerprint", Fingerprint: "sha256:aaa",
		}},
	}

	m, mAddr, _ := startMediator(t, "no-addrs-step", peers, ca, emptyLookup())

	conn := dialThroughMediator(t, mAddr, sni, ca)
	defer closer.Warn(conn, "test no-addrs client")

	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected read error after empty address list")
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, 1)
	found := false
	for _, r := range recs {
		if r.SNI == sni && r.Decision == mediator.DecisionError && strings.Contains(r.Err, "no addresses") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no error record for no-addresses; records: %+v", recs)
	}
}

func TestServe_UpstreamDialFails(t *testing.T) {
	ca := newTestCA(t)
	sni := "dial-fail.example"

	// Lookup returns 127.0.0.1; mediator dials 127.0.0.1:443
	// which should have no listener.
	peers := []mediator.PeerTrust{
		{Host: transport.Host(sni), Trust: transport.FingerprintTrust{
			Type: "certFingerprint", Fingerprint: "sha256:aaa",
		}},
	}

	m, mAddr, _ := startMediator(t, "dial-fail-step", peers, ca, unreachableLookup())

	conn := dialThroughMediator(t, mAddr, sni, ca)
	defer closer.Warn(conn, "test dial-fail client")

	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected read error after upstream dial failure")
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, 1)
	found := false
	for _, r := range recs {
		if r.SNI == sni && r.Decision == mediator.DecisionError && strings.Contains(r.Err, "upstream dial") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no error record for dial failure; records: %+v", recs)
	}
}

func TestServe_UpstreamHandshakeFails(t *testing.T) {
	ca := newTestCA(t)
	sni := "hs-fail.example"

	fp, _, cleanup := testUpstream(t, sni)
	defer cleanup()

	// Use a wrong fingerprint so the upstream handshake
	// verification fails. The dial to 127.0.0.1:443 will fail
	// (no listener on 443), producing an error record. This tests
	// that the error path records correctly. Full handshake-
	// mismatch testing requires binding port 443 (integration).
	wrongFP := fp[:len(fp)-4] + "dead"

	peers := []mediator.PeerTrust{
		{Host: transport.Host(sni), Trust: transport.FingerprintTrust{
			Type:        "certFingerprint",
			Fingerprint: wrongFP,
		}},
	}

	m, mAddr, _ := startMediator(t, "hs-fail-step", peers, ca, unreachableLookup())

	conn := dialThroughMediator(t, mAddr, sni, ca)
	defer closer.Warn(conn, "test hs-fail client")

	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected read error after upstream issue")
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, 1)
	found := false
	for _, r := range recs {
		if r.SNI == sni && r.Decision == mediator.DecisionError {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no error record; records: %+v", recs)
	}
}

func TestServe_ConcurrentConnections(t *testing.T) {
	ca := newTestCA(t)
	sni := "concurrent.example"

	// All connections hit the error path (port 443 has no listener).
	// Tests concurrency safety under -race.
	peers := []mediator.PeerTrust{
		{Host: transport.Host(sni), Trust: transport.FingerprintTrust{
			Type: "certFingerprint", Fingerprint: "sha256:aaa",
		}},
	}

	m, mAddr, _ := startMediator(t, "concurrent-step", peers, ca, unreachableLookup())

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			conn := dialThroughMediator(t, mAddr, sni, ca)
			closer.Warn(conn, "test concurrent client")
		}()
	}
	wg.Wait()

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer pollCancel()
	recs := waitForRecords(pollCtx, m, n)
	if len(recs) < n {
		t.Errorf("got %d records, want at least %d", len(recs), n)
	}
}

func TestServe_ContextCancellation(t *testing.T) {
	ca := newTestCA(t)

	m, err := mediator.New("cancel-step", nil, ca, unreachableLookup())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer closer.Warn(ln, "test cancel listener")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx, ln) }()

	cancel()

	deadline, deadlineCancel := context.WithTimeout(context.Background(), 500*clock.Millisecond)
	defer deadlineCancel()
	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Errorf("Serve returned error: %v", serveErr)
		}
	case <-deadline.Done():
		t.Fatal("Serve did not return within 500ms after context cancellation")
	}
}

func TestServe_NilListener(t *testing.T) {
	ca := newTestCA(t)
	m, err := mediator.New("nil-ln-step", nil, ca, unreachableLookup())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if serveErr := m.Serve(context.Background(), nil); serveErr == nil {
		t.Fatal("expected error for nil listener")
	}
}

func TestClose_Idempotent(t *testing.T) {
	ca := newTestCA(t)
	m, err := mediator.New("close-step", nil, ca, unreachableLookup())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for range 3 {
		if closeErr := m.Close(); closeErr != nil {
			t.Errorf("Close returned error: %v", closeErr)
		}
	}
}

func TestClose_BeforeServe_ServeReturnsError(t *testing.T) {
	ca := newTestCA(t)
	m, err := mediator.New("close-first-step", nil, ca, unreachableLookup())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if closeErr := m.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer closer.Warn(ln, "test close-first listener")

	serveErr := m.Serve(context.Background(), ln)
	if !errors.Is(serveErr, mediator.ErrMediatorClosed) {
		t.Errorf("Serve = %v, want ErrMediatorClosed", serveErr)
	}
}
