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
// For TCP connections, if CAFile is set the specified CA is used exclusively
// (pinned mode). If CAFile is empty, the system CA store is used as fallback.
// CertFile and KeyFile are optional (mutual TLS).
//
// Environment variables (following Docker/Podman convention):
//
//	CONTAINER_TLS_CA    path to CA certificate PEM (optional; system store if unset)
//	CONTAINER_TLS_CERT  path to client certificate PEM (optional, enables mTLS)
//	CONTAINER_TLS_KEY   path to client private key PEM (optional, enables mTLS)
type TLSConfig struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// LoadTLSConfig reads TLS paths from environment variables.
func LoadTLSConfig() TLSConfig {
	return TLSConfig{
		CAFile:   os.Getenv("CONTAINER_TLS_CA"),
		CertFile: os.Getenv("CONTAINER_TLS_CERT"),
		KeyFile:  os.Getenv("CONTAINER_TLS_KEY"),
	}
}

// IsPinned returns true if an explicit CA file is configured.
// When false, the system CA store is used.
func (c TLSConfig) IsPinned() bool {
	return c.CAFile != ""
}

// HasClientCert returns true if both client cert and key are configured.
func (c TLSConfig) HasClientCert() bool {
	return c.CertFile != "" && c.KeyFile != ""
}

// Build constructs a tls.Config. TLS 1.3 is the minimum version.
// If CAFile is set, only that CA is trusted (pinned mode). Otherwise the
// system CA store is used. Client authentication is added only if CertFile
// and KeyFile are both set.
func (c TLSConfig) Build() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if c.CAFile != "" {
		// Explicit CA -- exclusive pool (pinned mode).
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no valid certificates found in %s", c.CAFile)
		}
		cfg.RootCAs = caPool
	}
	// else: cfg.RootCAs remains nil -- Go uses system CA store.

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
