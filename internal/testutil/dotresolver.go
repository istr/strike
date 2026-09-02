package testutil

import (
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
	"github.com/istr/strike/internal/transport"
)

// TestResolverADN is the authentication domain name the hermetic DoT
// resolver presents. It is under the reserved .test TLD (RFC 6761), so it can
// never collide with a real name, and it is never resolved: the dial routes
// to the loopback literal and uses this only as the SNI and the reference
// identifier.
const TestResolverADN primitive.Host = "dot.test"

// StartDoTResolver starts a hermetic DNS-over-TLS resolver on 127.0.0.1 and
// returns a transport.Dialer that resolves through it, verified against
// TestResolverADN through an ephemeral CA. Every query is answered with a
// single A record for the queried name pointing at answer, which must be
// IPv4; the AAAA half of a dual-stack lookup therefore finds no record of its
// type and the lookup resolves to answer alone.
//
// Packages whose components take a *transport.Dialer need a real resolver to
// exercise the resolve-then-dial path, and this is the one that serves them
// all. The listener and its goroutines are torn down with the test.
func StartDoTResolver(t *testing.T, answer netip.Addr) *transport.Dialer {
	t.Helper()
	if !answer.Is4() {
		t.Fatalf("StartDoTResolver: answer %s must be IPv4", answer)
	}

	cert, caPath := resolverCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("StartDoTResolver: listen: %v", err)
	}
	t.Cleanup(func() { CloseLog(t, ln, "test DoT listener") })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go answerOneQuery(conn, answer.As4())
		}
	}()

	listen, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("StartDoTResolver: listener address %q: %v", ln.Addr(), err)
	}
	port := primitive.Port(listen.Port())
	dialer, err := transport.NewDialer(endpoint.DoT{
		ADN:  TestResolverADN,
		IP:   primitive.IPFromAddr(listen.Addr()),
		Port: &port,
		Trust: endpoint.CABundle{
			Type: "caBundle",
			Path: caPath,
		},
	})
	if err != nil {
		t.Fatalf("StartDoTResolver: %v", err)
	}
	return dialer
}

// resolverCert generates an ephemeral CA and a leaf it signs for
// TestResolverADN, writes the CA in PEM form into the test's own temporary
// directory, and returns the leaf together with the bundle path. The bundle
// is materialized on disk because a declared anchor carries a path; the
// directory is the test's, so the framework removes it.
func resolverCert(t *testing.T) (*tls.Certificate, primitive.AbsPath) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resolver CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "strike-test-dot-ca"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create resolver CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse resolver CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resolver key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "strike-test-dot"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{TestResolverADN.String()},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create resolver cert: %v", err)
	}

	path := filepath.Join(t.TempDir(), "resolver-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write resolver CA bundle: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, primitive.AbsPath(path)
}

// answerOneQuery reads one length-prefixed DNS query (RFC 7858 framing),
// writes back a single A record for the queried name, and closes. Every
// failure is silent: the connection is a test fixture, and the caller's
// lookup surfaces the outcome.
func answerOneQuery(conn net.Conn, answer [4]byte) {
	defer closer.Warn(conn, "test DoT conn")

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}
	var query dnsmessage.Message
	if err := query.Unpack(msg); err != nil || len(query.Questions) == 0 {
		return
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            query.ID,
			Response:      true,
			Authoritative: true,
		},
		Questions: query.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  query.Questions[0].Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.AResource{A: answer},
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
	var respLen [2]byte
	binary.BigEndian.PutUint16(respLen[:], uint16(size))
	if _, err := conn.Write(respLen[:]); err != nil {
		return
	}
	if _, err := conn.Write(packed); err != nil {
		return
	}
}
