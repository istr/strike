package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// resumptionADN is the name the resumption server's leaf certificate carries.
// It is under the reserved .test TLD (RFC 6761) and is never resolved: the
// dial routes to the loopback listener and uses this as the SNI and the
// reference identifier.
const resumptionADN primitive.Host = "resolver.test"

// TestDialer_ResumesResolverSession pins RFC 8310 section 9's requirement
// that the DNS client support TLS session resumption without server-side
// state. The first dial establishes a session and receives a ticket; the
// second must resume it. A nil session cache makes Go indicate no resumption
// support at all, so this test fails closed if the cache is ever dropped from
// the dialer.
func TestDialer_ResumesResolverSession(t *testing.T) {
	cert, caPath := resumptionCert(t)
	target := startResumptionServer(t, cert)
	port := primitive.Port(target.Port())
	d, err := NewDialer(endpoint.DoT{
		ADN:   resumptionADN,
		IP:    primitive.IPFromAddr(target.Addr()),
		Port:  &port,
		Trust: endpoint.CABundle{Type: "caBundle", Path: caPath},
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()

	first, err := d.dialResolver(ctx)
	if err != nil {
		t.Fatalf("first resolver dial: %v", err)
	}
	if first.conn.ConnectionState().DidResume {
		t.Error("first dial must not resume: no earlier session exists")
	}
	// The session ticket is a post-handshake message, so the client caches
	// the session only once it reads from the connection. One DNS roundtrip
	// is that read.
	nsRootExchange(t, first.conn)
	closer.Warn(first.conn, "first resolver conn")

	second, err := d.dialResolver(ctx)
	if err != nil {
		t.Fatalf("second resolver dial: %v", err)
	}
	defer closer.Warn(second.conn, "second resolver conn")
	if !second.conn.ConnectionState().DidResume {
		t.Error("second resolver dial must resume the first session (RFC 8310 section 9)")
	}
}

// startResumptionServer launches a TLS 1.3 DoT listener on the loopback that
// answers each connection's single query, and returns its address.
func startResumptionServer(t *testing.T, cert *tls.Certificate) netip.AddrPort {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { closer.Warn(ln, "resumption listener") })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go answerNSRoot(conn)
		}
	}()
	target, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener address %q: %v", ln.Addr(), err)
	}
	return target
}

// nsRootExchange sends one NS "." query over conn and reads the answer,
// failing the test if either half does not complete.
func nsRootExchange(t *testing.T, conn net.Conn) {
	t.Helper()
	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, RecursionDesired: false},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeNS,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	size := len(packed)
	if size > 65535 {
		t.Fatalf("query is %d bytes, too large for the DoT length prefix", size)
		return
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(size))
	if _, err := conn.Write(append(prefix[:], packed...)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read answer length: %v", err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, answer); err != nil {
		t.Fatalf("read answer: %v", err)
	}
}

// answerNSRoot reads one length-prefixed query and writes back a root NS
// answer. Every failure is silent: the connection is a test fixture and the
// caller's exchange surfaces the outcome.
func answerNSRoot(conn net.Conn) {
	defer closer.Warn(conn, "resumption server conn")
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}
	var query dnsmessage.Message
	if err := query.Unpack(msg); err != nil {
		return
	}
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true},
		Questions: query.Questions,
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
	packed, err := resp.Pack()
	if err != nil {
		return
	}
	size := len(packed)
	if size > 65535 {
		return
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(size))
	if _, err := conn.Write(append(prefix[:], packed...)); err != nil {
		return
	}
}

// resumptionCert generates an ephemeral CA and a leaf it signs for
// resumptionADN, writes the CA in PEM form into the test's own temporary
// directory, and returns the leaf together with the bundle path. It is
// generated here rather than taken from internal/testutil because that
// package imports this one.
func resumptionCert(t *testing.T) (*tls.Certificate, primitive.AbsPath) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "strike-test-resumption-ca"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "strike-test-resumption"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{resumptionADN.String()},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	path := filepath.Join(t.TempDir(), "resumption-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, primitive.AbsPath(path)
}
