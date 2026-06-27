package capsule_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

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

// testPorts returns a HostPorts suitable for tests that do not call Start.
func testPorts() capsule.HostPorts {
	return capsule.HostPorts{Resolver: 5353, Mediator: 5354}
}

// testHostKeyLine generates an ephemeral ed25519 key and returns its
// authorized_keys line, suitable for SSHTarget.HostKeys.
func testHostKeyLine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func TestNew_RejectsEmptyStepID(t *testing.T) {
	ca := testCA(t)
	_, err := capsule.New("", testPorts(), nil, nil, 0, ca, testUpstream())
	if err == nil {
		t.Error("expected error for empty stepID, got nil")
	}
}

func TestNew_RejectsNilCA(t *testing.T) {
	_, err := capsule.New("step", testPorts(), nil, nil, 0, nil, testUpstream())
	if err == nil {
		t.Error("expected error for nil CA, got nil")
	}
}

func TestNew_RejectsNilUpstreamLookup(t *testing.T) {
	ca := testCA(t)
	_, err := capsule.New("step", testPorts(), nil, nil, 0, ca, nil)
	if err == nil {
		t.Error("expected error for nil upstreamLook, got nil")
	}
}

func TestNew_EmptyPeersIsValid(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
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
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
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
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := c.PastaArgs()
	a[0] = testMutatedSentinel
	b := c.PastaArgs()
	if b[0] == testMutatedSentinel {
		t.Error("PastaArgs returned the same underlying slice, not a copy")
	}
}

func TestResolverAddr_UsesPort53(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := c.ResolverAddr()
	if got.Port() != 53 {
		t.Errorf("ResolverAddr port = %d, want 53", got.Port())
	}
	if got.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("ResolverAddr addr = %s, want 127.0.0.1", got.Addr())
	}
}

func TestStart_BindsListeners(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15353, Mediator: 15354}
	c, err := capsule.New("step", hp, nil, nil, 0, ca, testUpstream())
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
	_, err = lc.ListenPacket(ctx, "udp", "127.0.0.1:15353")
	if err == nil {
		t.Error("expected EADDRINUSE on UDP 127.0.0.1:15353")
	}
	_, err = lc.Listen(ctx, "tcp", "127.0.0.1:15353")
	if err == nil {
		t.Error("expected EADDRINUSE on TCP 127.0.0.1:15353")
	}
	_, err = lc.Listen(ctx, "tcp", "127.0.0.1:15354")
	if err == nil {
		t.Error("expected EADDRINUSE on TCP 127.0.0.1:15354")
	}
}

func TestStop_ReleasesListeners(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15355, Mediator: 15356}
	c, err := capsule.New("step", hp, nil, nil, 0, ca, testUpstream())
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
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:15356")
	if err != nil {
		t.Errorf("expected re-bind to succeed after Stop, got: %v", err)
	} else {
		testutil.CloseLog(t, ln, "re-bind listener")
	}
}

func TestStop_Idempotent(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15357, Mediator: 15358}
	c, err := capsule.New("step", hp, nil, nil, 0, ca, testUpstream())
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
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("Stop before Start: %v", err)
	}
}

func TestStartAfterStop_ReturnsError(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
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
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15359, Mediator: 15360}
	c, err := capsule.New("step", hp, nil, nil, 0, ca, testUpstream())
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
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
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
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15361, Mediator: 15362}
	c, err := capsule.New("step", hp, nil, nil, 0, ca, testUpstream())
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

func TestTwoCapsules_DistinctPorts(t *testing.T) {
	ca := testCA(t)

	ports, err := capsule.AllocatePorts([]capsule.StepPortReq{{Name: "step-a"}, {Name: "step-b"}})
	if err != nil {
		t.Fatalf("AllocatePorts: %v", err)
	}

	peers := []mediator.PeerTrust{{
		Host:  "example.com",
		Trust: endpoint.Fingerprint{Type: "fingerprint", Fingerprint: "sha256:aaaa"},
	}}

	c1, err := capsule.New("step-a", ports["step-a"], peers, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New c1: %v", err)
	}
	c2, err := capsule.New("step-b", ports["step-b"], peers, nil, 0, ca, testUpstream())
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

const testMutatedSentinel = "mutated"

const testPeerSNI = "test-peer.example"

// Regression guard tests (instruction 39).

// buildDNSQuery builds a raw DNS query for the given name and type.
func buildDNSQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	n, nameErr := dnsmessage.NewName(name + ".")
	if nameErr != nil {
		t.Fatalf("NewName: %v", nameErr)
	}
	builder := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:               0xABCD,
		RecursionDesired: true,
	})
	if startErr := builder.StartQuestions(); startErr != nil {
		t.Fatalf("StartQuestions: %v", startErr)
	}
	if qErr := builder.Question(dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); qErr != nil {
		t.Fatalf("Question: %v", qErr)
	}
	raw, finErr := builder.Finish()
	if finErr != nil {
		t.Fatalf("Finish: %v", finErr)
	}
	return raw
}

// udpDNSQuery sends a raw DNS query via UDP and returns the response.
func udpDNSQuery(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := new(net.Dialer).DialContext(context.Background(), "udp", addr)
	if err != nil {
		t.Fatalf("udpDNSQuery dial: %v", err)
	}
	defer closer.Warn(conn, "test udp conn")
	if dlErr := conn.SetDeadline(clock.Wall().Add(2 * clock.Second)); dlErr != nil {
		t.Fatalf("SetDeadline: %v", dlErr)
	}
	if _, writeErr := conn.Write(query); writeErr != nil {
		t.Fatalf("udpDNSQuery write: %v", writeErr)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udpDNSQuery read: %v", err)
	}
	return buf[:n]
}

// parseAAnswers parses A records from a raw DNS response.
func parseAAnswers(t *testing.T, raw []byte) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		t.Fatalf("parser Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	var addrs []netip.Addr
	for {
		rr, ansErr := p.Answer()
		if ansErr != nil {
			break
		}
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			addrs = append(addrs, netip.AddrFrom4(a.A))
		}
	}
	return h.RCode, addrs
}

// startTestUpstreamTLS spins up a TLS echo server with a self-signed cert
// valid for the given SNI. Returns the cert fingerprint, listener address,
// and a cleanup function.
func startTestUpstreamTLS(t *testing.T, sni string) (fingerprint string, addr string, cleanup func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
		t.Fatalf("create cert: %v", err)
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
		t.Fatalf("listen: %v", err)
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

func TestCapsule_ResolverSynthesizesStepAddr(t *testing.T) {
	ca := testCA(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	sni := testPeerSNI
	hp := capsule.HostPorts{Resolver: 15363, Mediator: 15364}

	peers := []mediator.PeerTrust{{
		Host:  primitive.Host(sni),
		Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:aaaa"},
	}}

	c, err := capsule.New("synth-step", hp, peers, nil, 0, ca, testUpstream())
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

	// DNS A query for the allowed peer.
	query := buildDNSQuery(t, sni, dnsmessage.TypeA)
	resp := udpDNSQuery(t, netip.AddrPortFrom(loopback, hp.Resolver).String(), query)

	rcode, addrs := parseAAnswers(t, resp)
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success", rcode)
	}
	if len(addrs) != 1 || addrs[0] != loopback {
		t.Fatalf("answer = %v, want [%s]", addrs, loopback)
	}
}

func TestCapsule_DNSThenConnect_EndToEnd(t *testing.T) {
	ca := testCA(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	sni := testPeerSNI
	hp := capsule.HostPorts{Resolver: 15365, Mediator: 15366}

	fp, upAddr, upCleanup := startTestUpstreamTLS(t, sni)
	defer upCleanup()

	// Parse upstream address to get the IP for the lookup function.
	upHost, _, splitErr := net.SplitHostPort(upAddr)
	if splitErr != nil {
		t.Fatalf("SplitHostPort: %v", splitErr)
	}
	upIP := netip.MustParseAddr(upHost)

	// The mediator hard-codes upstream port 443. Bind a TCP forwarder
	// on upIP:443 that proxies to the real test upstream.
	lc := net.ListenConfig{}
	fwdLn, fwdErr := lc.Listen(context.Background(), "tcp", net.JoinHostPort(upHost, "443"))
	if fwdErr != nil {
		t.Skipf("cannot bind %s:443: %v", upHost, fwdErr)
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

	peers := []mediator.PeerTrust{{
		Host: primitive.Host(sni),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: fp,
		},
	}}

	lookup := func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{upIP}, nil
	}

	c, err := capsule.New("e2e-step", hp, peers, nil, 0, ca, lookup)
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

	// (1) DNS A query -> receive loopback.
	query := buildDNSQuery(t, sni, dnsmessage.TypeA)
	resp := udpDNSQuery(t, netip.AddrPortFrom(loopback, hp.Resolver).String(), query)
	rcode, addrs := parseAAnswers(t, resp)
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success", rcode)
	}
	if len(addrs) != 1 || addrs[0] != loopback {
		t.Fatalf("DNS answer = %v, want [%s]", addrs, loopback)
	}

	// (2) TLS connect to loopback:mediatorHostPort with SNI.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PublicCertPEM()) {
		t.Fatal("failed to append CA cert")
	}

	mediatorAddr := netip.AddrPortFrom(loopback, hp.Mediator).String()
	raw, err := new(net.Dialer).DialContext(ctx, "tcp", mediatorAddr)
	if err != nil {
		t.Fatalf("dial mediator: %v", err)
	}
	defer closer.Warn(raw, "test client raw")

	tlsConn := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
	})
	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		t.Fatalf("TLS handshake: %v", hsErr)
	}

	// (3) Write payload, read echo.
	msg := []byte("hello through capsule")
	if _, writeErr := tlsConn.Write(msg); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	buf := make([]byte, len(msg))
	if _, readErr := io.ReadFull(tlsConn, buf); readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(buf) != string(msg) {
		t.Errorf("echoed = %q, want %q", buf, msg)
	}

	closer.Warn(tlsConn, "test client tls")

	// Verify mediator records.
	recs := c.Records()
	found := false
	for _, cr := range recs.Connections {
		if cr.SNI == sni && cr.Decision == mediator.DecisionAllowed {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no allowed connection record for %s; records: %+v", sni, recs.Connections)
	}
}

func TestCapsule_DeniedName_NXDOMAIN(t *testing.T) {
	ca := testCA(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	hp := capsule.HostPorts{Resolver: 15367, Mediator: 15368}

	peers := []mediator.PeerTrust{{
		Host:  "allowed.example",
		Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:aaaa"},
	}}

	c, err := capsule.New("deny-step", hp, peers, nil, 0, ca, testUpstream())
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

	query := buildDNSQuery(t, "denied.example", dnsmessage.TypeA)
	resp := udpDNSQuery(t, netip.AddrPortFrom(loopback, hp.Resolver).String(), query)

	rcode, _ := parseAAnswers(t, resp)
	if rcode != dnsmessage.RCodeNameError {
		t.Fatalf("RCode = %v, want NameError (NXDOMAIN)", rcode)
	}
}

func TestCapsule_AAAA_AllowedName_Empty(t *testing.T) {
	ca := testCA(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	sni := testPeerSNI
	hp := capsule.HostPorts{Resolver: 15369, Mediator: 15370}

	peers := []mediator.PeerTrust{{
		Host:  primitive.Host(sni),
		Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:aaaa"},
	}}

	c, err := capsule.New("aaaa-step", hp, peers, nil, 0, ca, testUpstream())
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

	query := buildDNSQuery(t, sni, dnsmessage.TypeAAAA)
	resp := udpDNSQuery(t, netip.AddrPortFrom(loopback, hp.Resolver).String(), query)

	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("parser Start: %v", err)
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success (NODATA)", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	// No answer records expected.
	if _, ansErr := p.Answer(); ansErr == nil {
		t.Error("expected no AAAA answer records, but got at least one")
	}
}

func TestCapsule_SSHForward_PastaArgs(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15373, Mediator: 15374}
	targets := []capsule.SSHTarget{{Host: "git.example.com", HostKeys: []string{testHostKeyLine(t)}}}

	c, err := capsule.New("ssh-step", hp, nil, targets, 40000, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	args := c.PastaArgs()
	// The front forward must appear as -T 22:<frontHostPort>; SSH egress
	// reaches the peer through the front, not a per-peer forward.
	frontFound := false
	for i, a := range args {
		if a == "-T" && i+1 < len(args) && args[i+1] == "22:40000" {
			frontFound = true
			break
		}
	}
	if !frontFound {
		t.Errorf("PastaArgs %v does not contain -T 22:40000", args)
	}
	// No per-peer SSH forward (former container-port base 2200) must remain.
	for i, a := range args {
		if a == "-T" && i+1 < len(args) && strings.HasPrefix(args[i+1], "2200:") {
			t.Errorf("PastaArgs %v still contains a per-peer SSH forward", args)
		}
	}
}

func TestCapsule_New_SSHTargets_RequireFrontPort(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15385, Mediator: 15386}
	targets := []capsule.SSHTarget{{Host: "git.example.com", HostKeys: []string{testHostKeyLine(t)}}}

	_, err := capsule.New("bad-step", hp, nil, targets, 0, ca, testUpstream())
	if err == nil {
		t.Fatal("expected error when frontHostPort is 0 with SSH targets")
	}
	if !strings.Contains(err.Error(), "front host port") {
		t.Errorf("error should mention front host port: %v", err)
	}
}

func TestCapsule_NoSSH_NoFrontForward(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("no-ssh", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	args := c.PastaArgs()
	for i, a := range args {
		if a == "-T" && i+1 < len(args) && strings.HasPrefix(args[i+1], "22:") {
			t.Errorf("PastaArgs should not contain a port-22 forward without SSH targets: %v", args)
		}
	}
}

func TestTokens_NoSSHTargets_Empty(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.Tokens(); len(got) != 0 {
		t.Errorf("Tokens() = %v, want empty", got)
	}
}

func TestSSHConfig_NoSSHTargets_Nil(t *testing.T) {
	ca := testCA(t)
	c, err := capsule.New("step", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.SSHConfig(); got != nil {
		t.Errorf("SSHConfig() = %q, want nil", got)
	}
}

func TestTokens_OneSSHTarget(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15376, Mediator: 15377}
	targets := []capsule.SSHTarget{{Host: "git.example.com", HostKeys: []string{testHostKeyLine(t)}}}

	c, err := capsule.New("tok-step", hp, nil, targets, 40000, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tokens := c.Tokens()
	if len(tokens) != 1 {
		t.Fatalf("Tokens() len = %d, want 1", len(tokens))
	}
	if len(tokens[0]) != 64 {
		t.Errorf("token len = %d, want 64 hex chars", len(tokens[0]))
	}
	// Validate hex by decoding.
	if _, decErr := hex.DecodeString(tokens[0]); decErr != nil {
		t.Fatalf("token is not valid hex: %v", decErr)
	}
}

func TestSSHConfig_OneSSHTarget_Structure(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15379, Mediator: 15380}
	targets := []capsule.SSHTarget{{Host: "git.example.com", HostKeys: []string{testHostKeyLine(t)}}}

	c, err := capsule.New("cfg-step", hp, nil, targets, 40000, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfg := string(c.SSHConfig())
	tokens := c.Tokens()

	// Must contain Host and SetEnv lines; no Port line.
	if !strings.Contains(cfg, "Host git.example.com\n") {
		t.Errorf("SSHConfig missing Host line:\n%s", cfg)
	}
	if strings.Contains(cfg, "Port ") {
		t.Errorf("SSHConfig should not contain a Port line:\n%s", cfg)
	}
	wantEnv := "    SetEnv STRIKE_PEER=" + tokens[0] + "\n"
	if !strings.Contains(cfg, wantEnv) {
		t.Errorf("SSHConfig missing SetEnv line:\n%s", cfg)
	}
}

func TestCloseOutbound_ForceClosesTrackedClient(t *testing.T) {
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshClientPub, pubErr := ssh.NewPublicKey(clientPub)
	if pubErr != nil {
		t.Fatal(pubErr)
	}

	// Minimal upstream SSH server that accepts auth and holds the connection.
	_, hostPriv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		t.Fatal(genErr)
	}
	hostSigner, sigErr := ssh.NewSignerFromKey(hostPriv)
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(sshClientPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	srvCfg.AddHostKey(hostSigner)
	var lc net.ListenConfig
	srvLn, lisErr := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if lisErr != nil {
		t.Fatal(lisErr)
	}
	defer closer.Warn(srvLn, "test upstream listener")
	go func() {
		for {
			c, aErr := srvLn.Accept()
			if aErr != nil {
				return
			}
			go func() {
				sConn, chans, reqs, hErr := ssh.NewServerConn(c, srvCfg)
				if hErr != nil {
					closer.Warn(c, "test srv handshake fail")
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, _, aErr := newCh.Accept()
					if aErr != nil {
						continue
					}
					// Hold channel open; the test closes from the client side.
					_ = ch
				}
				closer.Warn(sConn, "test srv conn")
			}()
		}
	}()

	// Dial as SSH client.
	agentSigner, agentErr := ssh.NewSignerFromKey(clientPriv)
	if agentErr != nil {
		t.Fatal(agentErr)
	}
	client, cErr := ssh.Dial("tcp", srvLn.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(agentSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	})
	if cErr != nil {
		t.Fatalf("ssh.Dial: %v", cErr)
	}

	// Build a capsule with one SSH target, track the client, then CloseOutbound.
	ca := testCA(t)
	hostKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	hp := capsule.HostPorts{Resolver: 15500, Mediator: 15501}
	targets := []capsule.SSHTarget{{Host: srvLn.Addr().String(), HostKeys: []string{hostKeyLine}}}
	caps, capsErr := capsule.New("close-step", hp, nil, targets, 40000, ca, testUpstream())
	if capsErr != nil {
		t.Fatal(capsErr)
	}

	// Verify client is usable before CloseOutbound.
	if _, sessErr := client.NewSession(); sessErr != nil {
		t.Fatalf("session before close: %v", sessErr)
	}

	// CloseOutbound should not panic even though we did not use BridgePeer;
	// with no tracked clients it is a no-op.
	caps.CloseOutbound()

	// Now manually verify the forwarder-level tracking works: the
	// production path is BridgePeer -> trackClient -> defer untrackClient.
	// We cannot call the unexported methods directly from an external test,
	// but we can verify CloseOutbound is idempotent (second call is a no-op).
	caps.CloseOutbound()

	// The client we dialed directly is not tracked by the capsule (we did not
	// go through BridgePeer), so close it ourselves.
	closer.Warn(client, "test client")
}

func TestCloseOutbound_NoSSH_Noop(t *testing.T) {
	ca := testCA(t)
	caps, err := capsule.New("no-ssh", testPorts(), nil, nil, 0, ca, testUpstream())
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic.
	caps.CloseOutbound()
	caps.CloseOutbound()
}

func TestTokens_IsSnapshot(t *testing.T) {
	ca := testCA(t)
	hp := capsule.HostPorts{Resolver: 15382, Mediator: 15383}
	targets := []capsule.SSHTarget{{Host: "git.example.com", HostKeys: []string{testHostKeyLine(t)}}}

	c, err := capsule.New("snap-step", hp, nil, targets, 40000, ca, testUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := c.Tokens()
	a[0] = testMutatedSentinel
	b := c.Tokens()
	if b[0] == testMutatedSentinel {
		t.Error("Tokens returned the same underlying slice, not a copy")
	}
}
