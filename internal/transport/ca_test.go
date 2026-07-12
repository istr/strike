package transport_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sync"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/transport"
)

func TestEphemeralCA_New_Success(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	pemBytes := ca.PublicCertPEM()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PublicCertPEM returned unparseable PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "test-lane" {
		t.Errorf("Subject OU = %v, want [test-lane]", cert.Subject.OrganizationalUnit)
	}
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}

	now := clock.Wall()
	if now.Sub(cert.NotBefore) > 2*clock.Minute {
		t.Errorf("NotBefore %v is more than 2 minutes before now %v", cert.NotBefore, now)
	}
	if cert.NotAfter.Sub(now) > 62*clock.Minute || cert.NotAfter.Sub(now) < 58*clock.Minute {
		t.Errorf("NotAfter %v is not within expected range of now %v", cert.NotAfter, now)
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not *ecdsa.PublicKey")
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", pub.Curve.Params().Name)
	}
}

func TestEphemeralCA_GetCertificate_HappyPath(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	tlsCert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "example.com")
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", leaf.DNSNames)
	}
	hasServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("ExtKeyUsage does not contain ServerAuth")
	}

	// Parse CA cert for pool and window comparison.
	block, _ := pem.Decode(ca.PublicCertPEM())
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	if !leaf.NotBefore.Equal(caCert.NotBefore) {
		t.Errorf("leaf NotBefore %v != CA NotBefore %v", leaf.NotBefore, caCert.NotBefore)
	}
	if !leaf.NotAfter.Equal(caCert.NotAfter) {
		t.Errorf("leaf NotAfter %v != CA NotAfter %v", leaf.NotAfter, caCert.NotAfter)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "example.com"}); err != nil {
		t.Errorf("leaf verification against CA pool failed: %v", err)
	}
}

func TestEphemeralCA_GetCertificate_EmptySNIRejected(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err == nil {
		t.Fatal("expected error for empty SNI")
	}
	if cert != nil {
		t.Error("expected nil cert for empty SNI")
	}
}

func TestEphemeralCA_GetCertificate_CacheHitSameSNI(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	hello := &tls.ClientHelloInfo{ServerName: "cache.example.com"}
	cert1, err := ca.GetCertificate(hello)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	cert2, err := ca.GetCertificate(hello)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if cert1 != cert2 {
		t.Error("same SNI returned different *tls.Certificate pointers; cache not consulted")
	}
}

func TestEphemeralCA_GetCertificate_DifferentSNI(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	cert1, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.example.com"})
	if err != nil {
		t.Fatalf("alpha: %v", err)
	}
	cert2, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "beta.example.com"})
	if err != nil {
		t.Fatalf("beta: %v", err)
	}
	if cert1 == cert2 {
		t.Error("different SNIs returned same *tls.Certificate pointer")
	}

	// Both should verify against the CA pool.
	block, _ := pem.Decode(ca.PublicCertPEM())
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	for _, name := range []string{"alpha.example.com", "beta.example.com"} {
		leaf, err := x509.ParseCertificate(cert1.Certificate[0])
		if name == "beta.example.com" {
			leaf, err = x509.ParseCertificate(cert2.Certificate[0])
		}
		if err != nil {
			t.Fatalf("parse leaf for %s: %v", name, err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
			t.Errorf("leaf for %s failed verification: %v", name, err)
		}
	}
}

func TestEphemeralCA_Close_RejectsSubsequentIssuance(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if closeErr := ca.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "post-close.example.com"})
	if !errors.Is(err, transport.ErrEphemeralCAClosed) {
		t.Errorf("err = %v, want ErrEphemeralCAClosed", err)
	}
	if cert != nil {
		t.Error("expected nil cert after Close")
	}

	if len(ca.PublicCertPEM()) == 0 {
		t.Error("PublicCertPEM returned empty after Close")
	}
	if ca.Fingerprint() == "" {
		t.Error("Fingerprint returned empty after Close")
	}
}

func TestEphemeralCA_Close_Idempotent(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := ca.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := ca.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestEphemeralCA_Concurrent_GetCertificate(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	const n = 50
	snis := []string{"a.example.com", "b.example.com", "c.example.com"}
	results := make([][]*tls.Certificate, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			results[idx] = make([]*tls.Certificate, len(snis))
			for j, sni := range snis {
				cert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
				if err != nil {
					t.Errorf("goroutine %d, sni %s: %v", idx, sni, err)
					return
				}
				results[idx][j] = cert
			}
		}(i)
	}
	wg.Wait()

	// All goroutines that fetched the same SNI should get the same pointer.
	for j, sni := range snis {
		ref := results[0][j]
		if ref == nil {
			continue
		}
		for i := 1; i < n; i++ {
			if results[i][j] == nil {
				continue
			}
			if results[i][j] != ref {
				t.Errorf("goroutine %d got different cert pointer for %s", i, sni)
			}
		}
	}
}

func TestEphemeralCA_Fingerprint_Stable(t *testing.T) {
	ca, err := transport.New("test-lane")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Warn(ca, "test CA")

	fp1 := ca.Fingerprint()
	fp2 := ca.Fingerprint()
	if fp1 != fp2 {
		t.Errorf("fingerprint unstable: %q vs %q", fp1, fp2)
	}

	// Manually compute from the PEM.
	block, _ := pem.Decode(ca.PublicCertPEM())
	sum := sha256.Sum256(block.Bytes)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if fp1.String() != want {
		t.Errorf("fingerprint = %q, want %q", fp1, want)
	}
}
