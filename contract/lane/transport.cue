// Transport-level types: the DoT resolver and HTTPS service endpoint
// declarations. A host is carried at the boundary as the endpoint.#Authority
// wire grammar and projected to the endpoint.Address concept; trust anchors and
// engine connection identity live in the endpoint package.
//
// These definitions share package lane so that lane.cue can reference
// them directly (#DNSResolver, #HTTPSEndpoint).
package lane

import "github.com/istr/strike/contract/endpoint"

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
	host:  endpoint.#Authority
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
	url:   =~"^https://"
	trust: endpoint.#Trust
}
