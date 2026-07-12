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
	"encoding/pem"
	"io"
	"math/big"
	"net"
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
// and its SHA-256 fingerprint string.
func testCertPair(t *testing.T, hosts ...string) (*tls.Certificate, primitive.Digest) {
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
	sum := sha256.Sum256(certDER)
	fingerprint := primitive.DigestFromHex(hex.EncodeToString(sum[:]))
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &tlsCert, fingerprint
}

// testCAAndServerCert generates a test CA and a server cert
// signed by it. Returns the server tls.Certificate and the CA
// cert in PEM form ready to write to disk for caBundle testing.
func testCAAndServerCert(t *testing.T, hosts ...string) (*tls.Certificate, []byte) {
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
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

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
	return &tlsCert, caCertPEM
}

// startTLSServer launches a TLS listener on 127.0.0.1 that
// accepts connections and keeps them open until the test ends.
// The test only exercises the handshake; payload is not relevant.
func startTLSServer(t *testing.T, config *tls.Config) endpoint.Address {
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
	return endpoint.MustParseAuthority(ln.Addr().String())
}

func TestDialVerified_FingerprintMatch(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: fingerprint,
	}
	conn, err := transport.DialVerified(ctx, addr, trust)
	if err != nil {
		t.Fatalf("DialVerified: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")
	id := conn.Identity()
	if id.LeafFingerprint != fingerprint {
		t.Errorf("Identity.LeafFingerprint = %q, want %q", id.LeafFingerprint, fingerprint)
	}
	if id.TLSVersion != tls.VersionTLS13 {
		t.Errorf("Identity.TLSVersion = 0x%x, want 0x%x (TLS 1.3)", id.TLSVersion, tls.VersionTLS13)
	}
	if id.PeerAddress.Authority() != addr.Authority() {
		t.Errorf("Identity.PeerAddress = %q, want %q", id.PeerAddress.Authority(), addr.Authority())
	}
}

func TestDialVerified_FingerprintMismatch(t *testing.T) {
	cert, _ := testCertPair(t, "127.0.0.1")
	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: primitive.DigestFromHex(strings.Repeat("0", 64)),
	}
	_, err := transport.DialVerified(ctx, addr, trust)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("error %q must mention 'fingerprint mismatch'", err)
	}
}

func TestDialVerified_CABundleValid(t *testing.T) {
	serverCert, caPEM := testCAAndServerCert(t, "127.0.0.1")
	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	})

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.CABundle{
		Type: "caBundle",
		Path: primitive.AbsPath(caPath),
	}
	conn, err := transport.DialVerified(ctx, addr, trust)
	if err != nil {
		t.Fatalf("DialVerified: %v", err)
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

func TestDialVerified_CABundleWrongCA(t *testing.T) {
	serverCert, _ := testCAAndServerCert(t, "127.0.0.1")
	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	})

	_, caPEMB := testCAAndServerCert(t, "127.0.0.1")
	dir := t.TempDir()
	caPath := filepath.Join(dir, "wrong-ca.pem")
	if err := os.WriteFile(caPath, caPEMB, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.CABundle{
		Type: "caBundle",
		Path: primitive.AbsPath(caPath),
	}
	_, err := transport.DialVerified(ctx, addr, trust)
	if err == nil {
		t.Fatal("expected CA verification error, got nil")
	}
}

func TestDialVerified_TLS12Accepted(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	// A TLS 1.2-only server must handshake successfully now that
	// the floor is 1.2.
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	serverCfg.MaxVersion = tls.VersionTLS12
	addr := startTLSServer(t, serverCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: fingerprint,
	}
	conn, err := transport.DialVerified(ctx, addr, trust)
	if err != nil {
		t.Fatalf("DialVerified: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")
	if conn.Identity().TLSVersion != tls.VersionTLS12 {
		t.Errorf("TLSVersion = 0x%x, want 0x%x (TLS 1.2)", conn.Identity().TLSVersion, tls.VersionTLS12)
	}
}

func TestDialVerified_TLS11Rejected(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	// A TLS 1.1-only server must be rejected: below the floor.
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	serverCfg.MinVersion = tls.VersionTLS10
	serverCfg.MaxVersion = tls.VersionTLS11
	addr := startTLSServer(t, serverCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: fingerprint,
	}
	_, err := transport.DialVerified(ctx, addr, trust)
	if err == nil {
		t.Fatal("expected handshake failure due to TLS version, got nil")
	}
}

type fakeTrust struct{}

func (fakeTrust) TrustType() endpoint.TrustType { return "fake" }

func TestBuildTLSConfig_UnknownTrust(t *testing.T) {
	_, err := transport.BuildTLSConfig(fakeTrust{})
	if err == nil {
		t.Fatal("expected error for unknown trust type")
	}
}

func TestDialVerified_SNIForFQDN(t *testing.T) {
	cert, fingerprint := testCertPair(t, "localhost")
	sniChan := make(chan string, 1)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			sniChan <- info.ServerName
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var sniConns []net.Conn
	t.Cleanup(func() {
		closer.Warn(ln, "test TLS listener")
		mu.Lock()
		defer mu.Unlock()
		for _, c := range sniConns {
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
			sniConns = append(sniConns, conn)
			mu.Unlock()
			go drainConn(conn)
		}
	}()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not a *net.TCPAddr", ln.Addr())
	}
	port := primitive.Port(tcpAddr.Port)
	addr := endpoint.Address{Host: "localhost", Port: &port}

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: fingerprint,
	}
	conn, err := transport.DialVerified(ctx, addr, trust)
	if err != nil {
		t.Fatalf("DialVerified: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")

	sniCtx, sniCancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer sniCancel()
	select {
	case sni := <-sniChan:
		if sni != "localhost" {
			t.Errorf("server saw SNI = %q, want %q", sni, "localhost")
		}
	case <-sniCtx.Done():
		t.Fatal("timeout waiting for SNI")
	}

	if conn.Identity().ServerName != "localhost" {
		t.Errorf("Identity.ServerName = %q, want %q", conn.Identity().ServerName, "localhost")
	}
}

func TestDialVerified_NoSNIForIPLiteral(t *testing.T) {
	cert, fingerprint := testCertPair(t, "127.0.0.1")
	addr := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: fingerprint,
	}
	conn, err := transport.DialVerified(ctx, addr, trust)
	if err != nil {
		t.Fatalf("DialVerified: %v", err)
	}
	defer closer.Warn(conn.Conn(), "test verified conn")
	if conn.Identity().ServerName != "" {
		t.Errorf("ServerName = %q, want empty (IP literal addr)", conn.Identity().ServerName)
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

func TestDialTCP(t *testing.T) {
	// Start a TCP listener for the success case.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { closer.Warn(ln, "test tcp listener") })
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			closer.Warn(c, "test tcp accepted")
		}
	}()

	tests := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{
			name: "valid IP literal",
			addr: ln.Addr().String(),
		},
		{
			name:    "hostname rejected",
			addr:    "example.com:443",
			wantErr: "requires an IP literal",
		},
		{
			name:    "missing port",
			addr:    "127.0.0.1",
			wantErr: "invalid tcp address",
		},
		{
			name:    "connection refused",
			addr:    "127.0.0.1:1",
			wantErr: "dial tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			conn, dialErr := transport.DialTCP(ctx, tt.addr)
			if tt.wantErr != "" {
				if dialErr == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(dialErr.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", dialErr, tt.wantErr)
				}
				return
			}
			if dialErr != nil {
				t.Fatalf("DialTCP: %v", dialErr)
			}
			closer.Warn(conn, "test tcp conn")
		})
	}
}
