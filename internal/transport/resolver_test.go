package transport_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
)

// startDNSTLSServer launches a TLS listener that speaks DNS-over-TLS:
// reads length-prefixed DNS queries, calls handler to produce a
// response, and writes the length-prefixed response back. Returns
// the listener address.
func startDNSTLSServer(t *testing.T, serverCert *tls.Certificate, handler func(*dnsmessage.Message) *dnsmessage.Message) string {
	t.Helper()
	config := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { closer.Warn(ln, "dns-tls listener") })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go serveDNSConn(conn, handler)
		}
	}()
	return ln.Addr().String()
}

// serveDNSConn handles one DNS-over-TLS connection: reads one
// query, calls handler, writes one response, then closes.
func serveDNSConn(conn net.Conn, handler func(*dnsmessage.Message) *dnsmessage.Message) {
	defer closer.Warn(conn, "dns conn")
	// Read 2-byte length prefix.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}
	var query dnsmessage.Message
	if err := query.Unpack(msg); err != nil {
		return
	}
	resp := handler(&query)
	if resp == nil {
		return
	}
	respBytes, err := resp.Pack()
	if err != nil {
		return
	}
	respSize := len(respBytes)
	if respSize > 65535 {
		return
	}
	var respLen [2]byte
	binary.BigEndian.PutUint16(respLen[:], uint16(respSize))
	if _, err := conn.Write(respLen[:]); err != nil {
		return
	}
	if _, err := conn.Write(respBytes); err != nil {
		return
	}
}

// aRecordHandler returns a handler that responds to A queries for
// the given name with the given IPv4 address.
func aRecordHandler(name string, ip [4]byte) func(*dnsmessage.Message) *dnsmessage.Message {
	return func(q *dnsmessage.Message) *dnsmessage.Message {
		resp := &dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:            q.ID,
				Response:      true,
				Authoritative: true,
			},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   300,
				},
				Body: &dnsmessage.AResource{A: ip},
			}},
		}
		return resp
	}
}

// nsRootHandler returns a handler that responds to NS queries for
// "." with a root NS record.
func nsRootHandler() func(*dnsmessage.Message) *dnsmessage.Message {
	return func(q *dnsmessage.Message) *dnsmessage.Message {
		resp := &dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:            q.ID,
				Response:      true,
				Authoritative: true,
			},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("."),
					Type:  dnsmessage.TypeNS,
					Class: dnsmessage.ClassINET,
					TTL:   3600,
				},
				Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName("a.root-servers.net.")},
			}},
		}
		return resp
	}
}

// servfailHandler returns a handler that responds with SERVFAIL.
func servfailHandler() func(*dnsmessage.Message) *dnsmessage.Message {
	return func(q *dnsmessage.Message) *dnsmessage.Message {
		resp := &dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.ID,
				Response: true,
				RCode:    dnsmessage.RCodeServerFailure,
			},
			Questions: q.Questions,
		}
		return resp
	}
}

func TestDialerLookupHost_HappyPath(t *testing.T) {
	cert, caPEM := testCAAndServerCert(t, "resolver.test")
	addr := startDNSTLSServer(t, cert, aRecordHandler("example.com.", [4]byte{93, 184, 216, 34}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := caBundleResolver(t, addr, writeCABundle(t, "resolver-ca.pem", caPEM))
	addrs, err := mustDialer(t, decl).LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address")
	}
	if addrs[0].String() != "93.184.216.34" {
		t.Errorf("got %s, want 93.184.216.34", addrs[0])
	}
}

func TestDialerLookupHost_CABundleMismatch(t *testing.T) {
	cert, _ := testCAAndServerCert(t, "resolver.test")
	addr := startDNSTLSServer(t, cert, aRecordHandler("example.com.", [4]byte{93, 184, 216, 34}))

	_, wrongCAPEM := testCAAndServerCert(t, "resolver.test")

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := caBundleResolver(t, addr, writeCABundle(t, "wrong-ca.pem", wrongCAPEM))
	addrs, err := mustDialer(t, decl).LookupHost(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for CA bundle mismatch, got nil")
	}
	if addrs != nil {
		t.Errorf("expected nil addrs, got %v", addrs)
	}
}

func TestDialerLookupHost_ServerUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer cancel()
	_, caPEM := testCAAndServerCert(t, "resolver.test")
	decl := caBundleResolver(t, "127.0.0.1:1", writeCABundle(t, "unused-ca.pem", caPEM))
	_, err := mustDialer(t, decl).LookupHost(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestDialerProbe_HappyPath(t *testing.T) {
	cert, caPEM := testCAAndServerCert(t, "resolver.test")
	addr := startDNSTLSServer(t, cert, nsRootHandler())
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := caBundleResolver(t, addr, writeCABundle(t, "resolver-ca.pem", caPEM))
	id, err := mustDialer(t, decl).Probe(ctx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if id.LeafFingerprint == "" {
		t.Error("expected non-empty leaf fingerprint from probe handshake")
	}
	if id.PeerAddress.Host != testResolverADN {
		t.Errorf("PeerAddress.Host = %q, want %q", id.PeerAddress.Host, testResolverADN)
	}
	if id.DialedAddr.String() != addr {
		t.Errorf("DialedAddr = %q, want %q", id.DialedAddr, addr)
	}
}

// TestDialerProbe_CABundleMismatch pins the V-property gate: the run-start
// probe rejects a resolver whose leaf is not certified by the declared CA
// bundle, which cmd/strike turns into a fatal abort before any attestation is
// sealed.
func TestDialerProbe_CABundleMismatch(t *testing.T) {
	serverCert, _ := testCAAndServerCert(t, "resolver.test")
	addr := startDNSTLSServer(t, serverCert, nsRootHandler())

	_, wrongCAPEM := testCAAndServerCert(t, "resolver.test")

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := caBundleResolver(t, addr, writeCABundle(t, "wrong-ca.pem", wrongCAPEM))
	if _, err := mustDialer(t, decl).Probe(ctx); err == nil {
		t.Fatal("expected error for CA bundle mismatch, got nil")
	}
}

// TestDialerProbe_VerifiesADNNotIP pins RFC 8310 section 3: the presented
// chain is accepted on the authentication domain name and never on the
// address the connection was routed to. The leaf carries only a DNS SAN, so
// a probe that matched on the dialed address could not succeed here, and one
// that matched on a different name could not fail there.
func TestDialerProbe_VerifiesADNNotIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()

	named, namedCAPEM := testCAAndServerCert(t, "resolver.test")
	namedAddr := startDNSTLSServer(t, named, nsRootHandler())
	decl := caBundleResolver(t, namedAddr, writeCABundle(t, "resolver-ca.pem", namedCAPEM))
	if _, err := mustDialer(t, decl).Probe(ctx); err != nil {
		t.Fatalf("probe must accept a leaf named %q with no IP SAN: %v", testResolverADN, err)
	}

	other, otherCAPEM := testCAAndServerCert(t, "other.test")
	otherAddr := startDNSTLSServer(t, other, nsRootHandler())
	otherDecl := caBundleResolver(t, otherAddr, writeCABundle(t, "other-ca.pem", otherCAPEM))
	if _, err := mustDialer(t, otherDecl).Probe(ctx); err == nil {
		t.Fatal("probe must reject a leaf naming a different DNS name, got nil")
	}
}

func TestDialerProbe_NoResponse(t *testing.T) {
	cert, caPEM := testCAAndServerCert(t, "resolver.test")
	addr := startDNSTLSServer(t, cert, servfailHandler())
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := caBundleResolver(t, addr, writeCABundle(t, "resolver-ca.pem", caPEM))
	if _, err := mustDialer(t, decl).Probe(ctx); err == nil {
		t.Fatal("expected error for SERVFAIL response, got nil")
	}
}

// TestDialerProbe_ErrorChainHasNoSystemResolverReference
// asserts that net.DNSError.Server has been cleared in the
// returned error chain. Without this clearing, Go's stdlib
// populates Server from /etc/resolv.conf even though the
// query went through our custom Dial, producing operator-
// confusing output. See clearMisleadingServerField.
func TestDialerProbe_ErrorChainHasNoSystemResolverReference(t *testing.T) {
	// Use any guaranteed-failing dial target. A non-listening
	// localhost port is the most reliable: no network access,
	// no test-server setup, fast and deterministic failure.
	_, caPEM := testCAAndServerCert(t, "resolver.test")
	decl := caBundleResolver(t, "127.0.0.1:1", writeCABundle(t, "unused-ca.pem", caPEM))
	ctx, cancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer cancel()

	_, err := mustDialer(t, decl).Probe(ctx)
	if err == nil {
		t.Fatal("expected error from unreachable resolver")
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.Server != "" {
			t.Errorf("DNSError.Server should be cleared, got %q", dnsErr.Server)
		}
	}
	// It is acceptable for the error chain to not contain a
	// *net.DNSError at all (the dial may fail before the
	// resolver wraps anything). The assertion above only fires
	// when a DNSError is present, which is the case worth
	// verifying.
}
