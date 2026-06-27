// Base peer types -- declared network trust contracts (ADR-005, ADR-007,
// ADR-047). Shared declarations named by the wire lane and the attest
// package.

package lane

import "github.com/istr/strike/contract/endpoint"

// Peers are container-egress trust contracts: each declares a
// destination the step container may reach during execution,
// together with the trust anchor strike uses to verify that
// destination's identity. Two protocols are supported:
//   - HTTPS peers: mediated through strike's per-step TLS
//     mediator (ADR-028); the container's egress is restricted to
//     declared peers and their connections are attested.
//   - SSH peers: known_hosts injection and ssh-agent-proxy
//     forwarding (ADR-024, ADR-025), with egress restricted to
//     declared peers via per-peer capsule forwards (ADR-033).
//
// There is no OCI peer type. A step's own image is pulled
// controller-side and verified against its pinned digest
// (#ImageRef); the digest is the integrity anchor, so no peer
// declaration is needed for it. A container that itself performs
// registry operations (DinD) reaches the registry over HTTPS and
// declares it as an HTTPS peer. See ADR-029.
//
// Peer is a discriminated union over the supported protocols. A
// non-empty peers list enumerates the destinations the step may
// reach; an absent or empty list yields an empty-allowlist capsule
// that permits no egress (ADR-033). Peers flow into the deploy
// attestation.
#Peer: (endpoint.#TLS | endpoint.#SSH) @go(-)
