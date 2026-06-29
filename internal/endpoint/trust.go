// Package endpoint holds the concept-tier value types for the external network
// endpoints strike contacts. This file carries the TLS server-trust vocabulary;
// the SSH host key (#HostKey) is generated into cue_types_gen.go. The package
// depends only on primitive.
package endpoint

// Trust is the interface implemented by TLS server-trust anchors (Fingerprint,
// CABundle). The CUE disjunction (#Fingerprint | #CABundle) is annotated @go(-)
// so the generator skips it; this hand-written interface is the Go-side union.
type Trust interface {
	// TrustType returns the discriminator ("certFingerprint", "caBundle").
	TrustType() string
}

// Fingerprint pins a server certificate by its SHA-256 fingerprint.
type Fingerprint struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// TrustType implements Trust.
func (t Fingerprint) TrustType() string { return t.Type }

// CABundle validates a server certificate against a CA bundle.
type CABundle struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// TrustType implements Trust.
func (t CABundle) TrustType() string { return t.Type }

// KnownHostsLine renders the host key as an OpenSSH known_hosts entry body:
// the key type, a space, and the base64-encoded public key.
func (k HostKey) KnownHostsLine() string {
	return k.KeyType + " " + string(k.Key)
}
