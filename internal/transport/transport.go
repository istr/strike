// Package transport defines the trust-anchor types and host
// constraint used by every TLS-based peer kind in strike
// (HTTPS peers, the DoT resolver, future TLS-trusted peers).
// The package is positioned beneath lane in the directional
// dependency graph: lane imports transport, never the reverse.
//
// Higher-level transport functionality (TLS dialing with
// verified trust anchors, connection-identity capture) lives
// in this package but is added in a follow-up PR. This file
// contains only the types whose CUE source is specs/base-transport.cue.
package transport

import (
	"encoding/json"
	"fmt"
)

// Host is a hostname or IPv4 literal, optionally with :port.
// Lowercase ASCII; punycode required for internationalized domains.
type Host string

// TLSTrust is the interface implemented by TLS peer trust
// anchors (FingerprintTrust, CABundleTrust). The CUE disjunction
// (#FingerprintTrust | #CABundleTrust) is annotated @go(-) so
// the generator skips it; this hand-written interface provides
// the Go-side discriminated union.
type TLSTrust interface {
	// TrustType returns the discriminator ("certFingerprint", "caBundle").
	TrustType() string
}

// FingerprintTrust pins a peer's server certificate by SHA-256 fingerprint.
type FingerprintTrust struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// TrustType implements TLSTrust.
func (t FingerprintTrust) TrustType() string { return t.Type }

// CABundleTrust validates a peer's server certificate against a CA bundle.
type CABundleTrust struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// TrustType implements TLSTrust.
func (t CABundleTrust) TrustType() string { return t.Type }

// DNSResolver declares the DoT resolver strike uses for all
// peer hostname resolution within a lane run. Mandatory per
// ADR-028; every lane has exactly one. The trust anchor follows
// the same TLSTrust vocabulary as HTTPS peers, so verification
// mechanics are reused.
type DNSResolver struct {
	Trust TLSTrust `json:"trust"`
	Host  Host     `json:"host"`
}

// HTTPSEndpoint is a TLS-only service base URL with a mandatory
// declared trust anchor. The CUE schema (#HTTPSEndpoint) admits
// only https:// URLs, so a plaintext endpoint is a parse error,
// not a runtime rejection. Clients append fixed well-known API
// paths to the base URL.
type HTTPSEndpoint struct {
	Trust TLSTrust `json:"trust"`
	URL   string   `json:"url"`
}

// EngineConnection is the control-plane-observed identity of the engine
// transport, a discriminated union over the connection kind. The CUE
// disjunction (#EngineUnix | #EngineTLS | #EngineMTLS) is annotated @go(-)
// so the generator skips it; this hand-written interface provides the
// Go-side union, mirroring TLSTrust. Layer V (cpObserved): the control
// plane reads these facts off the TLS handshake itself.
type EngineConnection interface {
	// ConnectionType returns the discriminator ("unix", "tls", "mtls").
	ConnectionType() string
}

// EngineUnix is a Unix-socket engine connection: no certificate identity.
type EngineUnix struct {
	Type string `json:"type"`
}

// ConnectionType implements EngineConnection.
func (c EngineUnix) ConnectionType() string { return c.Type }

// EngineTLS is a one-way-TLS engine connection. CATrustType records how the
// engine's server certificate was trusted ("pinned" explicit CA, or
// "system" OS trust store).
type EngineTLS struct {
	Type                  string `json:"type"`
	CATrustType           string `json:"caTrustType"`
	ServerCertFingerprint string `json:"serverCertFingerprint"`
	ServerCertSubject     string `json:"serverCertSubject,omitempty"`
	ServerCertIssuer      string `json:"serverCertIssuer,omitempty"`
}

// ConnectionType implements EngineConnection.
func (c EngineTLS) ConnectionType() string { return c.Type }

// EngineMTLS is a mutual-TLS engine connection: the EngineTLS server identity
// plus the controller's own client-certificate identity.
type EngineMTLS struct {
	Type                  string `json:"type"`
	CATrustType           string `json:"caTrustType"`
	ServerCertFingerprint string `json:"serverCertFingerprint"`
	ServerCertSubject     string `json:"serverCertSubject,omitempty"`
	ServerCertIssuer      string `json:"serverCertIssuer,omitempty"`
	ClientCertFingerprint string `json:"clientCertFingerprint"`
	ClientCertSubject     string `json:"clientCertSubject,omitempty"`
}

// ConnectionType implements EngineConnection.
func (c EngineMTLS) ConnectionType() string { return c.Type }

// UnmarshalEngineConnection decodes one engine-connection JSON object into the
// concrete branch named by its "type" discriminator. Exported for
// internal/deploy, which dispatches sealed.engine through it. Mirrors the
// peer/observed-identity dispatch helpers.
func UnmarshalEngineConnection(data []byte) (EngineConnection, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, fmt.Errorf("engine connection missing")
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("engine connection: %w", err)
	}
	switch probe.Type {
	case "unix":
		var c EngineUnix
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("decode unix engine connection: %w", err)
		}
		return c, nil
	case "tls":
		var c EngineTLS
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("decode tls engine connection: %w", err)
		}
		return c, nil
	case "mtls":
		var c EngineMTLS
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("decode mtls engine connection: %w", err)
		}
		return c, nil
	case "":
		return nil, fmt.Errorf("engine connection missing type discriminator")
	default:
		return nil, fmt.Errorf("unknown engine connection type %q", probe.Type)
	}
}
