// Package endpoint holds the concept-tier value types for the external network
// endpoints strike contacts. The TLS trust anchor and the SSH host key are both
// generated into cue_types_gen.go; this file carries the two behaviours the
// generator cannot express. The package depends only on primitive.
package endpoint

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/istr/strike/internal/primitive"
)

// Parse decodes the anchor into an X.509 certificate. Base64 and DER are
// decoded here and nowhere else, so the leaf comparison in transport and the
// mode reconciliation in lane read the same bytes the same way (ADR-056 D7).
func (c Certificate) Parse() (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(c.Cert.String())
	if err != nil {
		return nil, fmt.Errorf("endpoint: trust anchor is not standard base64: %w", err)
	}
	cert, parseErr := x509.ParseCertificate(der)
	if parseErr != nil {
		return nil, fmt.Errorf("endpoint: trust anchor is not a DER certificate: %w", parseErr)
	}
	return cert, nil
}

// CertificateFromDER is the inverse of Parse: it wraps a DER certificate as a
// declared anchor in the given mode. Callers that hold a certificate -- a test
// that just minted one, a reader of the harness PKI -- go through here rather
// than encoding the body themselves, so the encoding lives in one place on
// both sides.
func CertificateFromDER(der []byte, mode CertificateMode) Certificate {
	return Certificate{
		Mode: mode,
		Cert: primitive.Base64(base64.StdEncoding.EncodeToString(der)),
	}
}

// KnownHostsLine renders the host key as an OpenSSH known_hosts entry body:
// the key type, a space, and the base64-encoded public key.
func (k HostKey) KnownHostsLine() string {
	return string(k.KeyType) + " " + k.Key.String()
}
