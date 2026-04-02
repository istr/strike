package container_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/istr/strike/internal/container"
)

// testPKI holds ephemeral certificates for TLS testing.
type testPKI struct {
	caPool        *x509.CertPool
	caCertPEM     []byte
	serverCert    tls.Certificate
	clientCert    tls.Certificate
	clientCertPEM []byte
	clientKeyPEM  []byte
}

// generateTestPKI creates an ephemeral CA, server cert (SAN: 127.0.0.1),
// and client cert. All certs use ECDSA P-256 and expire in one hour.
func generateTestPKI(t *testing.T) *testPKI {
	t.Helper()

	// 1. CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "strike-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
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
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// 2. Server cert for 127.0.0.1
	serverCert := generateLeafCert(t, "strike-test-engine", caKey, caCert,
		[]net.IP{net.IPv4(127, 0, 0, 1)},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	// 3. Client cert
	clientCert, clientCertPEM, clientKeyPEM := generateClientCert(t, "strike-test-controller", caKey, caCert)

	return &testPKI{
		caPool:        caPool,
		caCertPEM:     caCertPEM,
		serverCert:    serverCert,
		clientCert:    clientCert,
		clientCertPEM: clientCertPEM,
		clientKeyPEM:  clientKeyPEM,
	}
}

func generateLeafCert(t *testing.T, cn string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, ips []net.IP, usage []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key for %s: %v", cn, err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		IPAddresses:  ips,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert for %s: %v", cn, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key for %s: %v", cn, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("TLS keypair for %s: %v", cn, err)
	}
	return cert
}

func generateClientCert(t *testing.T, cn string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("client TLS keypair: %v", err)
	}
	return cert, certPEM, keyPEM
}

func writePEM(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Test engine constructors.

// newTLSTestEngine starts a TLS test server with server-only verification.
// The engine verifies the server cert but does NOT present a client cert.
func newTLSTestEngine(t *testing.T, handler http.Handler) container.Engine {
	t.Helper()
	pki := generateTestPKI(t)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		MinVersion:   tls.VersionTLS13,
		// No ClientAuth -- server-only TLS
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.crt"), pki.caCertPEM)

	t.Setenv("CONTAINER_TLS_CA", filepath.Join(dir, "ca.crt"))
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	addr := strings.Replace(srv.URL, "https://", "tcp://", 1)
	eng, err := container.NewFromAddress(addr)
	if err != nil {
		t.Fatalf("NewFromAddress(%s): %v", addr, err)
	}
	return eng
}

// newMTLSTestEngine starts a TLS test server with mutual authentication.
// Both sides present and verify certificates.
func newMTLSTestEngine(t *testing.T, handler http.Handler) container.Engine {
	t.Helper()
	pki := generateTestPKI(t)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.crt"), pki.caCertPEM)
	writePEM(t, filepath.Join(dir, "client.crt"), pki.clientCertPEM)
	writePEM(t, filepath.Join(dir, "client.key"), pki.clientKeyPEM)

	t.Setenv("CONTAINER_TLS_CA", filepath.Join(dir, "ca.crt"))
	t.Setenv("CONTAINER_TLS_CERT", filepath.Join(dir, "client.crt"))
	t.Setenv("CONTAINER_TLS_KEY", filepath.Join(dir, "client.key"))

	addr := strings.Replace(srv.URL, "https://", "tcp://", 1)
	eng, err := container.NewFromAddress(addr)
	if err != nil {
		t.Fatalf("NewFromAddress(%s): %v", addr, err)
	}
	return eng
}
