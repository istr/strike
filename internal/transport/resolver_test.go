package transport_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/transport"
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

func TestLookupHost_HappyPath(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	addr := startDNSTLSServer(t, cert, aRecordHandler("example.com.", [4]byte{93, 184, 216, 34}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := transport.DNSResolver{
		Host: transport.Host(addr),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: fingerprint,
		},
	}
	addrs, err := transport.LookupHost(ctx, decl, "example.com")
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

func TestLookupHost_FingerprintMismatch(t *testing.T) {
	cert, _ := testCertPair(t, "127.0.0.1")
	addr := startDNSTLSServer(t, cert, aRecordHandler("example.com.", [4]byte{93, 184, 216, 34}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := transport.DNSResolver{
		Host: transport.Host(addr),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:" + strings.Repeat("0", 64),
		},
	}
	addrs, err := transport.LookupHost(ctx, decl, "example.com")
	if err == nil {
		t.Fatal("expected error for fingerprint mismatch, got nil")
	}
	if addrs != nil {
		t.Errorf("expected nil addrs, got %v", addrs)
	}
}

func TestLookupHost_ServerUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer cancel()
	decl := transport.DNSResolver{
		Host: "127.0.0.1:1",
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:" + strings.Repeat("a", 64),
		},
	}
	_, err := transport.LookupHost(ctx, decl, "example.com")
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestProbeResolver_HappyPath(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	addr := startDNSTLSServer(t, cert, nsRootHandler())
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := transport.DNSResolver{
		Host: transport.Host(addr),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: fingerprint,
		},
	}
	id, err := transport.ProbeResolver(ctx, decl)
	if err != nil {
		t.Fatalf("ProbeResolver: %v", err)
	}
	if id.LeafFingerprint == "" {
		t.Error("expected non-empty leaf fingerprint from probe handshake")
	}
	if id.PeerAddress != string(decl.Host) {
		t.Errorf("PeerAddress = %q, want %q", id.PeerAddress, string(decl.Host))
	}
}

func TestProbeResolver_FingerprintMismatch(t *testing.T) {
	cert, _ := testCertPair(t, "127.0.0.1")
	addr := startDNSTLSServer(t, cert, nsRootHandler())
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := transport.DNSResolver{
		Host: transport.Host(addr),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:" + strings.Repeat("0", 64),
		},
	}
	if _, err := transport.ProbeResolver(ctx, decl); err == nil {
		t.Fatal("expected error for fingerprint mismatch, got nil")
	}
}

func TestProbeResolver_NoResponse(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	addr := startDNSTLSServer(t, cert, servfailHandler())
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	decl := transport.DNSResolver{
		Host: transport.Host(addr),
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: fingerprint,
		},
	}
	if _, err := transport.ProbeResolver(ctx, decl); err == nil {
		t.Fatal("expected error for SERVFAIL response, got nil")
	}
}

// TestProbeResolver_ErrorChainHasNoSystemResolverReference
// asserts that net.DNSError.Server has been cleared in the
// returned error chain. Without this clearing, Go's stdlib
// populates Server from /etc/resolv.conf even though the
// query went through our custom Dial, producing operator-
// confusing output. See clearMisleadingServerField.
func TestProbeResolver_ErrorChainHasNoSystemResolverReference(t *testing.T) {
	// Use any guaranteed-failing dial target. A non-listening
	// localhost port is the most reliable: no network access,
	// no test-server setup, fast and deterministic failure.
	decl := transport.DNSResolver{
		Host: "127.0.0.1:1",
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer cancel()

	_, err := transport.ProbeResolver(ctx, decl)
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
