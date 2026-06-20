package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/istr/strike/internal/clock"
)

// EphemeralCA is a per-lane-run certificate authority. The
// private key is generated in process memory and disposed via
// Close; no key material reaches disk. Suitable for direct use
// with the PR-20 TLS mediator via tls.Config.GetCertificate.
//
// Lifetime and disposal:
//   - Construct one instance per strike run.
//   - The CA cert and all issued leaf certs share a 1h validity
//     window starting at lane begin.
//   - Call Close at lane end; subsequent GetCertificate calls
//     return an error. PublicCertPEM and Fingerprint continue
//     to work after Close (they expose non-secret material).
//
// Concurrency: GetCertificate is safe for concurrent use across
// goroutines. Leaves are cached per SNI; same SNI returns the
// same *tls.Certificate across handshakes within a lane run.
//
// Replacement, not augmentation: the public cert is intended to
// replace the step container's system CA bundle, not augment
// it. See docs/ADR-028-step-container-egress-mediation.md, "On the legitimacy
// of TLS termination in this context", for the architectural reasoning.
type EphemeralCA struct {
	notBefore clock.Time
	notAfter  clock.Time
	privKey   *ecdsa.PrivateKey
	cert      *x509.Certificate
	cache     map[string]*tls.Certificate
	laneID    string
	certSHA   string
	certPEM   []byte
	mu        sync.RWMutex
	closed    bool
}

// ErrEphemeralCAClosed is returned by GetCertificate after Close.
var ErrEphemeralCAClosed = errors.New("transport: ephemeral CA closed")

// New constructs a fresh EphemeralCA. The CA is valid from
// (clock.Wall() - 1 minute) until (clock.Wall() + 1 hour + 1
// minute); the small skew tolerance accommodates clock
// granularity between cert issuance and consumer verification.
// The lane ID is included in the CA's Subject OU for forensic
// traceability; it does not affect verification.
func New(laneID string) (*EphemeralCA, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("transport: generate CA key: %w", err)
	}

	now := clock.Wall()
	notBefore := now.Add(-clock.Minute)
	notAfter := now.Add(clock.Hour + clock.Minute)

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("transport: generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "strike-ephemeral-CA",
			Organization:       []string{"strike"},
			OrganizationalUnit: []string{laneID},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("transport: create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("transport: parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	sum := sha256.Sum256(certDER)
	certSHA := "sha256:" + hex.EncodeToString(sum[:])

	return &EphemeralCA{
		laneID:    laneID,
		privKey:   privKey,
		cert:      cert,
		certPEM:   certPEM,
		certSHA:   certSHA,
		notBefore: notBefore,
		notAfter:  notAfter,
		cache:     make(map[string]*tls.Certificate),
	}, nil
}

// PublicCertPEM returns the CA's public certificate as PEM
// bytes. The bytes are not secret; the caller is free to write
// them to disk, mount them, or transmit them. PR-22 uses these
// bytes to populate the step container's CA bundle (replacing
// the system CA bundle).
func (c *EphemeralCA) PublicCertPEM() []byte {
	return c.certPEM
}

// Fingerprint returns the SHA-256 fingerprint of the CA's
// public certificate, formatted as "sha256:<64 lowercase hex>".
// PR-23 will include this in deploy attestation as part of the
// captured runtime context.
func (c *EphemeralCA) Fingerprint() string {
	return c.certSHA
}

// GetCertificate issues (or returns a cached) leaf TLS
// certificate for the SNI in hello. Suitable for direct use as
// tls.Config.GetCertificate in the PR-20 mediator.
//
// The SNI is the leaf's CommonName and the single DNSName in
// the SAN extension. Leaf private keys are ECDSA P-256.
//
// Leaf NotBefore and NotAfter inherit the CA's window. All
// certs in a lane run expire together at lane begin + 1h. Lanes
// running longer than 1h will observe TLS validation failures
// mid-run; this is a known limitation and the per-lane TTL is
// not configurable at this time.
func (c *EphemeralCA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := hello.ServerName
	if sni == "" {
		return nil, fmt.Errorf("transport: GetCertificate called with empty SNI")
	}

	// Fast path: cache hit.
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrEphemeralCAClosed
	}
	if cached, ok := c.cache[sni]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	// Slow path: issue and cache.
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrEphemeralCAClosed
	}
	if cached, ok := c.cache[sni]; ok {
		return cached, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("transport: generate leaf key for %q: %w", sni, err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("transport: generate leaf serial for %q: %w", sni, err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:   c.notBefore,
		NotAfter:    c.notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{sni},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.cert, &leafKey.PublicKey, c.privKey)
	if err != nil {
		return nil, fmt.Errorf("transport: create leaf cert for %q: %w", sni, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}
	c.cache[sni] = tlsCert
	return tlsCert, nil
}

// Close disposes the CA's in-memory key material and the cached
// leaf private keys. Subsequent GetCertificate calls return
// ErrEphemeralCAClosed. PublicCertPEM and Fingerprint continue
// to work; they return non-secret material.
//
// Close is idempotent. The first call disposes; subsequent
// calls return nil without effect.
func (c *EphemeralCA) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.privKey = nil
	c.cache = nil
	return nil
}

// randomSerial returns a 128-bit cryptographically random
// serial number suitable for x509.Certificate.SerialNumber. RFC
// 5280 requires positive integers; rand.Int over [0, 2^128)
// returns a non-negative big.Int, which CreateCertificate
// handles correctly.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
