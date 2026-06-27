package lane

import "github.com/istr/strike/internal/endpoint"

// Peer is the interface implemented by all peer types
// (endpoint.TLS, endpoint.SSH). The CUE disjunction is
// annotated @go(-) so the generator skips it; this hand-written interface
// provides the Go-side discriminated union, parallel to DeployMethod and
// ProvenanceRecord.
//
// Peers are container-egress trust contracts only. There is no
// OCI peer type: a step's own image is controller-pulled and
// digest-verified (the digest is the integrity anchor, not a
// peer), and container-initiated registry traffic is an HTTPS
// peer. See ADR-029.
type Peer interface {
	// Addr returns the peer's network address.
	Addr() endpoint.Address
}
