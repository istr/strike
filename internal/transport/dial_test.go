package transport_test

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
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// drainConn triggers the server-side TLS handshake by reading
// from the connection until it closes or errors. Runs in a
// goroutine; the error is expected and irrelevant.
func drainConn(c net.Conn) {
	var buf [1]byte
	for {
		if _, err := c.Read(buf[:]); err != nil {
			return
		}
	}
}

// testCertPair generates a self-signed ECDSA P-256 cert valid
// for the given hosts (DNS names and/or IPs). Returns the cert
// and the leaf-mode anchor that pins it.
func testCertPair(t *testing.T, hosts ...string) (*tls.Certificate, endpoint.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "strike-test"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &tlsCert, endpoint.CertificateFromDER(certDER, endpoint.CertificateModeLeaf)
}

// testCAAndServerCert generates a test CA and a server cert
// signed by it. Returns the server tls.Certificate and the CA
// as a rootca-mode anchor.
func testCAAndServerCert(t *testing.T, hosts ...string) (*tls.Certificate, endpoint.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "strike-test-ca"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "strike-test-server"},
		NotBefore:             clock.Wall().Add(-clock.Hour),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
		} else {
			serverTemplate.DNSNames = append(serverTemplate.DNSNames, h)
		}
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}
	return &tlsCert, endpoint.CertificateFromDER(caCertDER, endpoint.CertificateModeRootca)
}

// startTLSServer launches a TLS listener on 127.0.0.1 that
// accepts connections and keeps them open until the test ends.
// The test only exercises the handshake; payload is not relevant.
func startTLSServer(t *testing.T, config *tls.Config) netip.AddrPort {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		closer.Warn(ln, "test TLS listener")
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			closer.Warn(c, "test TLS accepted conn")
		}
	})
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go drainConn(conn)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func TestDialResolved_LeafMatch(t *testing.T) {
	cert, trust := testCertPair(t, "127.0.0.1")
	dst := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	conn, err := transport.DialResolved(ctx, dst, "127.0.0.1", trust)
	if err != nil {
		t.Fatalf("DialResolved: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")
	id := conn.Identity()
	if want := leafDigest(cert); id.LeafFingerprint != want {
		t.Errorf("Identity.LeafFingerprint = %q, want %q", id.LeafFingerprint, want)
	}
	if id.TLSVersion != tls.VersionTLS13 {
		t.Errorf("Identity.TLSVersion = 0x%x, want 0x%x (TLS 1.3)", id.TLSVersion, tls.VersionTLS13)
	}
	if got := string(id.PeerAddress.Authority()); got != dst.String() {
		t.Errorf("Identity.PeerAddress = %q, want %q", got, dst)
	}
}

// TestDialResolved_RejectsUnusableArguments pins that routing and identity
// are both required and are both checked before any packet is sent: an
// address that is not resolved cannot be dialed, and an empty verification
// name is an error rather than a silent downgrade to an unverified peer.
func TestDialResolved_RejectsUnusableArguments(t *testing.T) {
	trust := testutil.AnchorTrust()
	tests := []struct {
		name       string
		serverName primitive.Host
		dst        netip.AddrPort
		wantErr    string
	}{
		{
			name:       "zero address",
			dst:        netip.AddrPort{},
			serverName: "peer.example",
			wantErr:    "requires a resolved address and port",
		},
		{
			name:       "zero port",
			dst:        netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
			serverName: "peer.example",
			wantErr:    "requires a resolved address and port",
		},
		{
			name:       "empty verification name",
			dst:        netip.MustParseAddrPort("127.0.0.1:443"),
			serverName: "",
			wantErr:    "requires a verification name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transport.DialResolved(context.Background(), tt.dst, tt.serverName, trust)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestDialResolved_LeafMismatch(t *testing.T) {
	cert, _ := testCertPair(t, "127.0.0.1")
	dst := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	// A leaf anchor over a different certificate: the server presents the
	// first, the declaration pins the second.
	_, trust := testCertPair(t, "127.0.0.1")
	_, err := transport.DialResolved(ctx, dst, "127.0.0.1", trust)
	if err == nil {
		t.Fatal("expected leaf mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "does not match the declared leaf anchor") {
		t.Errorf("error %q must report the leaf mismatch", err)
	}
}

func TestDialResolved_RootCAValid(t *testing.T) {
	serverCert, trust := testCAAndServerCert(t, "127.0.0.1")
	dst := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	conn, err := transport.DialResolved(ctx, dst, "127.0.0.1", trust)
	if err != nil {
		t.Fatalf("DialResolved: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")
	id := conn.Identity()
	if id.TLSVersion != tls.VersionTLS13 {
		t.Errorf("TLSVersion = 0x%x, want TLS 1.3", id.TLSVersion)
	}
	if len(id.PeerCertificates) == 0 {
		t.Error("expected at least one peer certificate")
	}
}

func TestDialResolved_RootCAWrongCA(t *testing.T) {
	serverCert, _ := testCAAndServerCert(t, "127.0.0.1")
	dst := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	})

	// The anchor is deliberately the other CA.
	_, wrongCA := testCAAndServerCert(t, "127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	_, err := transport.DialResolved(ctx, dst, "127.0.0.1", wrongCA)
	if err == nil {
		t.Fatal("expected CA verification error, got nil")
	}
}

// TestDialResolved_RootCAWrongName pins that the verification name is
// enforced and not merely sent: the presented chain validates against the
// declared root, but it carries no SAN for the name the caller asked for,
// and the handshake fails.
func TestDialResolved_RootCAWrongName(t *testing.T) {
	serverCert, trust := testCAAndServerCert(t, "other.example")
	dst := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	_, err := transport.DialResolved(ctx, dst, "asked-for.example", trust)
	if err == nil {
		t.Fatal("expected certificate-name error, got nil")
	}
	if !strings.Contains(err.Error(), "asked-for.example") {
		t.Errorf("error %q must name the requested identity", err)
	}
}

func TestDialResolved_TLS12Accepted(t *testing.T) {
	cert, trust := testCertPair(t, "127.0.0.1")
	// A TLS 1.2-only server must handshake successfully now that
	// the floor is 1.2.
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	serverCfg.MaxVersion = tls.VersionTLS12
	dst := startTLSServer(t, serverCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	conn, err := transport.DialResolved(ctx, dst, "127.0.0.1", trust)
	if err != nil {
		t.Fatalf("DialResolved: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")
	if conn.Identity().TLSVersion != tls.VersionTLS12 {
		t.Errorf("TLSVersion = 0x%x, want 0x%x (TLS 1.2)", conn.Identity().TLSVersion, tls.VersionTLS12)
	}
}

func TestDialResolved_TLS11Rejected(t *testing.T) {
	cert, trust := testCertPair(t, "127.0.0.1")
	// A TLS 1.1-only server must be rejected: below the floor.
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	serverCfg.MinVersion = tls.VersionTLS10
	serverCfg.MaxVersion = tls.VersionTLS11
	dst := startTLSServer(t, serverCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	_, err := transport.DialResolved(ctx, dst, "127.0.0.1", trust)
	if err == nil {
		t.Fatal("expected handshake failure due to TLS version, got nil")
	}
}

// leafDigest is the SHA-256 fingerprint ConnectionIdentity records for a
// presented leaf, computed over the certificate the test minted.
func leafDigest(cert *tls.Certificate) primitive.Digest {
	sum := sha256.Sum256(cert.Certificate[0])
	return primitive.DigestFromHex(hex.EncodeToString(sum[:]))
}

// TestBuildTLSConfig_RejectsUnusableAnchor pins the two ways a declared
// anchor fails before any packet is sent: a mode the dialer does not know,
// and a body that is not a certificate.
func TestBuildTLSConfig_RejectsUnusableAnchor(t *testing.T) {
	unknownMode := testutil.AnchorTrust()
	unknownMode.Mode = "fake"
	notACert := testutil.AnchorTrust()
	notACert.Cert = "not-base64!"
	tests := []struct {
		name    string
		wantErr string
		trust   endpoint.Certificate
	}{
		{name: "unknown mode", trust: unknownMode, wantErr: "unknown trust mode"},
		{name: "body is not base64", trust: notACert, wantErr: "not standard base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transport.BuildTLSConfig(tt.trust)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestDialResolved_VerificationNameForms pins both shapes a declared peer
// takes under chain verification, where an empty ServerName would abort the
// handshake outright. A hostname is sent in the SNI extension; an address
// literal is suppressed per RFC 6066. Either way the name is the reference
// identifier the presented certificate is verified against, so a cert whose
// only SAN is the matching DNS name or IP address is accepted.
func TestDialResolved_VerificationNameForms(t *testing.T) {
	tests := []struct {
		name       string
		san        string
		serverName primitive.Host
		wantSNI    string
	}{
		{name: "hostname is sent as SNI", san: "localhost", serverName: "localhost", wantSNI: "localhost"},
		{name: "address literal is suppressed", san: "127.0.0.1", serverName: "127.0.0.1", wantSNI: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCert, trust := testCAAndServerCert(t, tt.san)
			sniChan := make(chan string, 1)
			dst := startTLSServer(t, &tls.Config{
				Certificates: []tls.Certificate{*serverCert},
				MinVersion:   tls.VersionTLS13,
				MaxVersion:   tls.VersionTLS13,
				GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
					sniChan <- info.ServerName
					return nil, nil
				},
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
			defer cancel()
			conn, err := transport.DialResolved(ctx, dst, tt.serverName, trust)
			if err != nil {
				t.Fatalf("DialResolved: %v", err)
			}
			defer closer.Warn(conn.Conn(), "test verified conn")

			sniCtx, sniCancel := context.WithTimeout(context.Background(), 2*clock.Second)
			defer sniCancel()
			select {
			case sni := <-sniChan:
				if sni != tt.wantSNI {
					t.Errorf("server saw SNI = %q, want %q", sni, tt.wantSNI)
				}
			case <-sniCtx.Done():
				t.Fatal("timeout waiting for the ClientHello")
			}

			if got := conn.Identity().PeerAddress.Host; got != tt.serverName {
				t.Errorf("Identity.PeerAddress.Host = %q, want %q", got, tt.serverName)
			}
		})
	}
}

func TestDialUnixSocket(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
	}{
		{
			name: "valid socket",
			setup: func(t *testing.T) string {
				t.Helper()
				return testutil.StartEchoSocket(t)
			},
		},
		{
			name: "regular file",
			setup: func(t *testing.T) string {
				t.Helper()
				p := filepath.Join(t.TempDir(), "not-a-socket")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: "not a unix socket",
		},
		{
			name: "nonexistent path",
			setup: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "no-such-file")
			},
			wantErr: "resolve unix socket",
		},
		{
			name: "symlink to valid socket",
			setup: func(t *testing.T) string {
				t.Helper()
				target := testutil.StartEchoSocket(t)
				link := filepath.Join(t.TempDir(), "link.sock")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
		},
		{
			name: "broken symlink",
			setup: func(t *testing.T) string {
				t.Helper()
				link := filepath.Join(t.TempDir(), "broken.sock")
				if err := os.Symlink("/nonexistent/target", link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			wantErr: "resolve unix socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			ctx := context.Background()
			conn, err := transport.DialUnixSocket(ctx, path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DialUnixSocket: %v", err)
			}
			defer testutil.CloseLog(t, conn, "test unix conn")

			want := []byte("dial unix socket test")
			if _, wErr := conn.Write(want); wErr != nil {
				t.Fatalf("write: %v", wErr)
			}
			if cwErr := conn.CloseWrite(); cwErr != nil {
				t.Fatalf("close write: %v", cwErr)
			}
			got, rErr := io.ReadAll(conn)
			if rErr != nil {
				t.Fatalf("read: %v", rErr)
			}
			if string(got) != string(want) {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}
