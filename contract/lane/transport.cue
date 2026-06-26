// Transport-level types: host constraint, resolver/endpoint addresses, and
// engine connection identity. Trust anchors live in the endpoint package.
//
// These definitions share package lane so that lane.cue can reference
// them directly (#Host, #DNSResolver). The @go(-) annotations suppress
// Go code generation via gengotypes; the Go types are hand-written in
// internal/transport/transport.go so they live in a separate Go package.
// Directional dependency: internal/lane imports internal/transport.
package lane

import "github.com/istr/strike/contract/endpoint"

// ----------------------------------------------------------------
// Host constraint: hostname or IPv4 literal, optionally with port.
// Lowercase ASCII; punycode required for internationalized domains.
// Used by every peer kind that addresses a network endpoint by
// name (HTTPS, SSH, DoT resolver, future TLS-trusted peers).
// OCI registries use a separate constraint because their format
// includes path segments.
// ----------------------------------------------------------------
#Host: =~"^[a-z0-9.-]+(:[0-9]+)?$" @go(-)

// ----------------------------------------------------------------
// DNS resolver declaration.
//
// Every lane declares exactly one DoT (DNS-over-TLS) resolver
// under the top-level `resolver:` field of #Lane. The resolver
// is treated as a peer in the same trust sense as any HTTPS peer
// (per ADR-028): the lane author supplies a TLS trust anchor
// (`certFingerprint` or `caBundle`), the controller verifies
// the resolver's TLS identity on the first handshake of a lane
// run, and that identity flows into the deploy attestation.
//
// The host must be an IP literal (IPv4, IPv6, IPv6 in brackets,
// each optionally with a `:port` suffix). FQDN entries are
// rejected because the resolver is itself the resolution authority
// and cannot resolve its own hostname before it can be reached.
//
// The IP-literal constraint is enforced in Go (lane.validateResolver
// called from lane.Parse), not in this schema. Encoding IPv4 plus
// IPv6 plus bracketed-IPv6-with-port in a CUE regex would be a
// 200-400-character maintenance liability with no net cross-
// implementation benefit -- a Rust verifier reading this schema
// would parse with std::net::IpAddr, not by mirroring a regex.
// The Go check using net/netip is the canonical enforcement;
// this comment is the schema-level intent record.
// ----------------------------------------------------------------
#DNSResolver: {
	@go(-)
	host:  #Host
	trust: endpoint.#Trust
}

// ----------------------------------------------------------------
// HTTPS endpoint: a TLS-only base URL with a mandatory declared
// trust anchor. Used by service clients that dial fixed well-known
// API paths under the base (ADR-040 keyless endpoints). The
// https:// regex makes a plaintext URL a parse error, not a
// runtime rejection ("Enforcement is structural, not
// discretionary").
// ----------------------------------------------------------------
#HTTPSEndpoint: {
	@go(-)
	url:   =~"^https://"
	trust: endpoint.#Trust
}

// ----------------------------------------------------------------
// Engine connection: the control-plane-observed identity of the
// engine transport, a discriminated union over the connection kind
// (mirrors #Peer / endpoint.#Trust). Consumed by the deploy attestation at
// sealed.engine via the artifact.cue bridge. Layer V (cpObserved):
// the control plane reads these facts off the TLS handshake itself.
//
// The discriminator is `type`. A Unix socket carries no certificate
// identity; tls adds the observed server-cert identity and how it was
// trusted; mtls adds the controller's own client-cert identity.
// ----------------------------------------------------------------
#EngineConnection: (#EngineUnix | #EngineTLS | #EngineMTLS) @go(-)

#EngineUnix: {
	@go(-)
	type: "unix"
}

// EngineServerTLS is the observed engine server-cert identity shared by
// the tls and mtls variants. Not a connection on its own (no discriminator).
#EngineServerTLS: {
	@go(-)

	// caTrustType is how the engine's server certificate was trusted:
	// "pinned" (explicit CA) or "system" (OS trust store).
	caTrustType: "pinned" | "system"
	// serverCertFingerprint is sha256:<hex> of the engine's leaf cert,
	// observed by CP during the TLS handshake.
	serverCertFingerprint: string
	// serverCertSubject / serverCertIssuer are the Subject CN and Issuer CN
	// of that leaf certificate, observed in the same handshake.
	serverCertSubject?: string
	serverCertIssuer?:  string
}

#EngineTLS: {
	#EngineServerTLS
	@go(-)
	type: "tls"
}

#EngineMTLS: {
	#EngineServerTLS
	@go(-)
	type: "mtls"
	// clientCertFingerprint is sha256:<hex> of the controller's own cert;
	// clientCertSubject is its Subject CN.
	clientCertFingerprint: string
	clientCertSubject?:    string
}
