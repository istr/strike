// Package transport defines the resolver/endpoint address types used by
// strike's TLS-based peers. Trust anchors and engine connection identity live
// in internal/endpoint.
// The package is positioned beneath lane in the directional
// dependency graph: lane imports transport, never the reverse.
//
// Higher-level transport functionality (TLS dialing with
// verified trust anchors, connection-identity capture) lives
// in this package but is added in a follow-up PR.
package transport

import "github.com/istr/strike/internal/endpoint"

// DNSResolver declares the DoT resolver strike uses for all
// peer hostname resolution within a lane run. Mandatory per
// ADR-028; every lane has exactly one. The trust anchor follows
// the same endpoint.Trust vocabulary as HTTPS peers, so verification
// mechanics are reused.
type DNSResolver struct {
	Trust   endpoint.Trust   `json:"trust"`
	Address endpoint.Address `json:"host"`
}

// HTTPSEndpoint is a TLS-only service base URL with a mandatory
// declared trust anchor. The CUE schema (#HTTPSEndpoint) admits
// only https:// URLs, so a plaintext endpoint is a parse error,
// not a runtime rejection. Clients append fixed well-known API
// paths to the base URL.
type HTTPSEndpoint struct {
	Trust endpoint.Trust `json:"trust"`
	URL   string         `json:"url"`
}
