package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// StartDoTResolver starts a hermetic DNS-over-TLS resolver on 127.0.0.1 and
// returns a transport.Dialer that resolves through it, pinned to the
// resolver's ephemeral certificate. Every query is answered with a single A
// record for the queried name pointing at answer, which must be IPv4; the
// AAAA half of a dual-stack lookup therefore finds no record of its type and
// the lookup resolves to answer alone.
//
// Packages whose components take a *transport.Dialer need a real resolver to
// exercise the resolve-then-dial path, and this is the one that serves them
// all. The listener and its goroutines are torn down with the test.
func StartDoTResolver(t *testing.T, answer netip.Addr) *transport.Dialer {
	t.Helper()
	if !answer.Is4() {
		t.Fatalf("StartDoTResolver: answer %s must be IPv4", answer)
	}

	cert, fingerprint := loopbackCert(t)
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

	dialer, err := transport.NewDialer(endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority(ln.Addr().String()),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: fingerprint,
		},
	})
	if err != nil {
		t.Fatalf("StartDoTResolver: %v", err)
	}
	return dialer
}

// loopbackCert generates an ephemeral self-signed ECDSA P-256 certificate
// valid for 127.0.0.1 and returns it with its SHA-256 fingerprint.
func loopbackCert(t *testing.T) (*tls.Certificate, primitive.Digest) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate resolver key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "strike-test-dot"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create resolver cert: %v", err)
	}
	sum := sha256.Sum256(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		primitive.DigestFromHex(hex.EncodeToString(sum[:]))
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
