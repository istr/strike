// Transport-level types: host constraint and TLS trust anchors.
//
// These definitions share package lane so that lane.cue can reference
// them directly (#Host, #TLSTrust). The @go(-) annotations suppress
// Go code generation via gengotypes; the Go types are hand-written in
// internal/transport/transport.go so they live in a separate Go package.
// Directional dependency: internal/lane imports internal/transport.
package lane

// ----------------------------------------------------------------
// Host constraint: hostname or IPv4 literal, optionally with port.
// Lowercase ASCII; punycode required for internationalized domains.
// Used by every peer kind that addresses a network endpoint by
// name (HTTPS, SSH, DoT resolver, future TLS-trusted peers).
// OCI registries use a separate constraint because their format
// includes path segments.
// ----------------------------------------------------------------
#Host: string & =~"^[a-z0-9.-]+(:[0-9]+)?$" @go(-)

// ----------------------------------------------------------------
// Trust anchors for TLS-based peers.
//
// TLSTrust is a discriminated union over the two enforceable
// server-side trust mechanisms strike supports. The system trust
// store is explicitly not an option (deferred per ADR-021); all
// trust is per-peer-declared.
//
// The discriminator is `mode`. Cross-implementation readers can
// dispatch on `mode` without parsing the rest of the object.
// ----------------------------------------------------------------
#TLSTrust: (#FingerprintTrust | #CABundleTrust) @go(-)

#FingerprintTrust: {
	@go(-)
	mode:        "cert_fingerprint"
	fingerprint: =~"^sha256:[a-f0-9]{64}$"
}

#CABundleTrust: {
	@go(-)
	mode: "ca_bundle"
	// path is a container-internal path. The executor mounts the lane-
	// relative bundle file there in Phase 2; in Phase 1 the field is
	// declaratory only.
	path: #AbsPath
}

// ----------------------------------------------------------------
// DNS resolver declaration.
//
// Every lane declares exactly one DoT (DNS-over-TLS) resolver
// under the top-level `resolver:` field of #Lane. The resolver
// is treated as a peer in the same trust sense as any HTTPS peer
// (per ADR-028): the lane author supplies a TLS trust anchor
// (`cert_fingerprint` or `ca_bundle`), the controller verifies
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
	trust: #TLSTrust
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
	url:   string & =~"^https://"
	trust: #TLSTrust
}
