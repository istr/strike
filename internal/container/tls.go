package container

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
)

// TLSConfig holds paths for TLS configuration.
//
// For TCP connections, CAFile is required (server verification).
// CertFile and KeyFile are optional (mutual TLS).
//
// Environment variables (following Docker/Podman convention):
//
//	CONTAINER_TLS_CA    path to CA certificate PEM (required for TCP)
//	CONTAINER_TLS_CERT  path to client certificate PEM (optional, enables mTLS)
//	CONTAINER_TLS_KEY   path to client private key PEM (optional, enables mTLS)
type TLSConfig struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// LoadTLSConfig reads TLS paths from environment variables.
func LoadTLSConfig() *TLSConfig {
	return &TLSConfig{
		CAFile:   os.Getenv("CONTAINER_TLS_CA"),
		CertFile: os.Getenv("CONTAINER_TLS_CERT"),
		KeyFile:  os.Getenv("CONTAINER_TLS_KEY"),
	}
}

// HasCA returns true if a CA certificate path is configured.
func (c *TLSConfig) HasCA() bool {
	return c != nil && c.CAFile != ""
}

// HasClientCert returns true if both client cert and key are configured.
func (c *TLSConfig) HasClientCert() bool {
	return c != nil && c.CertFile != "" && c.KeyFile != ""
}

// Build constructs a tls.Config. TLS 1.3 is the minimum version.
// Server verification is always enabled. Client authentication is added
// only if CertFile and KeyFile are both set.
func (c *TLSConfig) Build() (*tls.Config, error) {
	caCert, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("no valid certificates found in %s", c.CAFile)
	}

	cfg := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	}

	if c.HasClientCert() {
		cert, certErr := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if certErr != nil {
			return nil, fmt.Errorf("load client certificate: %w", certErr)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// CertFingerprint computes the SHA-256 fingerprint of a DER-encoded
// certificate. Returns "sha256:<hex>".
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TLSIdentity holds the cryptographic identity information captured from
// a TLS connection. Populated after the first successful API call.
type TLSIdentity struct {
	// ServerFingerprint is the SHA-256 fingerprint of the engine's leaf
	// certificate. Always set for TCP connections.
	ServerFingerprint string

	// ServerSubject is the Subject CN of the engine's certificate.
	ServerSubject string

	// ServerIssuer is the Issuer CN of the engine's certificate.
	ServerIssuer string

	// ClientFingerprint is the SHA-256 fingerprint of the controller's
	// certificate. Empty if mTLS is not configured.
	ClientFingerprint string

	// ClientSubject is the Subject CN of the controller's certificate.
	// Empty if mTLS is not configured.
	ClientSubject string

	// Mutual is true if both sides presented certificates.
	Mutual bool
}
