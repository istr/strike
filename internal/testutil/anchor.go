package testutil

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/endpoint"
)

// AnchorCertB64 is artifact 1 of docs/FIXTURE-TRUST-ANCHOR.md: the self-signed
// CA certificate over the RFC 9500 testECCP256 key, DER-encoded in standard
// padded base64. It is the anchor for every declaration-only test site -- one
// where a peer is declared and the declaration inspected, but nothing is
// dialed. A test that stands up a TLS server generates its own material
// instead, because an anchor has to match the certificate the server presents
// and the private key behind this one is deliberately not in the tree.
const AnchorCertB64 = "MIIBuzCCAWGgAwIBAgIBATAKBggqhkjOPQQDAjBEMR0wGwYDVQQKDBRzdHJpa2UgdGVzdCBtYXRlcmlhbDEjMCEGA1UEAwwac3RyaWtlIGZpeHR1cmUgdGVzdCBhbmNob3IwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEQxHTAbBgNVBAoMFHN0cmlrZSB0ZXN0IG1hdGVyaWFsMSMwIQYDVQQDDBpzdHJpa2UgZml4dHVyZSB0ZXN0IGFuY2hvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJQnKjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRbcKeYF/ef9jfS9+PcRGwhCde71DAKBggqhkjOPQQDAgNIADBFAiEAgS0Tvd1/A38U+EpMiaA1GtTjXCX11rqbLgUQf5iRhhgCIDnuZnbVCpcQjNQLMsrhhzlFRTlAWOVNlS0apM4uHD/E"

// AnchorTrust returns AnchorCertB64 as a rootca trust declaration.
func AnchorTrust() endpoint.Certificate {
	return endpoint.Certificate{Mode: endpoint.CertificateModeRootca, Cert: AnchorCertB64}
}

// CertificateFromPEMFile reads a PEM file and returns its first certificate as
// a rootca trust anchor. The local sigstore harness mints its PKI on every
// rebuild, so a caller that dials the harness reads the current material here
// rather than carrying a literal.
func CertificateFromPEMFile(path string) (endpoint.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return endpoint.Certificate{}, fmt.Errorf("read trust anchor %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return endpoint.Certificate{}, fmt.Errorf("trust anchor %q holds no PEM certificate", path)
	}
	return endpoint.CertificateFromDER(block.Bytes, endpoint.CertificateModeRootca), nil
}
