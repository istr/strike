// Package transport defines the trust-anchor types and host
// constraint used by every TLS-based peer kind in strike
// (HTTPS peers, the DoT resolver, future TLS-trusted peers).
// The package is positioned beneath lane in the directional
// dependency graph: lane imports transport, never the reverse.
//
// Higher-level transport functionality (TLS dialing with
// verified trust anchors, connection-identity capture) lives
// in this package but is added in a follow-up PR. This file
// contains only the types whose CUE source is specs/transport.cue.
package transport

// Host is a hostname or IPv4 literal, optionally with :port.
// Lowercase ASCII; punycode required for internationalized domains.
type Host string

// TLSTrust is the interface implemented by TLS peer trust
// anchors (FingerprintTrust, CABundleTrust). The CUE disjunction
// (#FingerprintTrust | #CABundleTrust) is annotated @go(-) so
// the generator skips it; this hand-written interface provides
// the Go-side discriminated union.
type TLSTrust interface {
	// TrustMode returns the discriminator ("cert_fingerprint", "ca_bundle").
	TrustMode() string
}

// FingerprintTrust pins a peer's server certificate by SHA-256 fingerprint.
type FingerprintTrust struct {
	Mode        string `json:"mode"`
	Fingerprint string `json:"fingerprint"`
}

// TrustMode implements TLSTrust.
func (t FingerprintTrust) TrustMode() string { return t.Mode }

// CABundleTrust validates a peer's server certificate against a CA bundle.
type CABundleTrust struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
}

// TrustMode implements TLSTrust.
func (t CABundleTrust) TrustMode() string { return t.Mode }

// DNSResolver declares the DoT resolver strike uses for all
// peer hostname resolution within a lane run. Mandatory per
// ADR-028; every lane has exactly one. The trust anchor follows
// the same TLSTrust vocabulary as HTTPS peers, so verification
// mechanics are reused.
type DNSResolver struct {
	Trust TLSTrust `json:"trust"`
	Host  Host     `json:"host"`
}
