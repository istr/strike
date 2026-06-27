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
#Peer: (#HTTPSPeer | #SSHPeer) @go(-)

// The host @go redirects name the contract/ package, not internal/: `make
// generate` rewrites contract/ -> internal/ across the generated files, so a
// redirect to a package that also contributes a generated type to the same
// file must use the pre-rewrite contract/ path. Both references then normalize
// to one import; the literal internal/ path would emit a duplicate import.

// HTTPSPeer declares an HTTPS endpoint together with its server-trust anchor.
#HTTPSPeer: {
	@go(HTTPSPeer)
	type:  "https"         @go(Type)
	host:  #Host           @go(Host,type="github.com/istr/strike/contract/endpoint".Address)
	trust: endpoint.#Trust @go(Trust,type="github.com/istr/strike/contract/endpoint".Trust)
}

// SSHPeer declares an SSH endpoint with explicit known_hosts entries.
// Strike creates and injects a global known_hosts entry in the
// step container.
// For client-side authentication, strike forwards an ssh-agent socket
// if available.
#SSHPeer: {
	@go(SSHPeer)
	type: "ssh" @go(Type)
	host: #Host @go(Host,type="github.com/istr/strike/contract/endpoint".Address)
	knownHosts: [...endpoint.#HostKey] @go(KnownHosts)
}
