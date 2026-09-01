# ADR-012: Engine Identity Captured in Every Attestation

## Status

Accepted.

> **Superseded in part by [ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md);
> amended by [ADR-037](ADR-037-two-engine-trust-layers.md) and
> [ADR-042](ADR-042-field-naming-camelcase.md):** three later decisions
> revise this record, unmarked until now. Placement (ADR-040 D3): the
> Decision clause "Every deploy attestation includes an `engine`
> field" is displaced -- engine context is a separate predicate of a
> strike-defined type, co-attached as its own referrer
> (`strike.dev/predicates/engine-context/v1`), carrying the engine
> identity, transport fingerprint, and engine-reported actions;
> because it is physically separate, the sealed provenance verifies
> without trusting any engine-relayed claim, and which predicates
> `strike verify` requires depends on the trust mode. Classification
> (ADR-037): `#EngineRecord` is marked informational wholesale -- it
> mixes a controller-observed cert fingerprint with self-reported
> version/rootless in one unmarked record, and it is not a trust
> input either way, the engine being untrusted. That qualifies this
> ADR's framing that a verifier "needs to assess the trust level"
> from it: the capture stands as recorded observation; it does not
> gate the sealed statement. Naming (ADR-042): the snake_case wire
> names here predate the camelCase rename of strike's own fields.
> Verified against the tree, the trust-mode field is spelled
> `caTrustType` ("pinned" | "system") in
> `contract/endpoint/engine.cue` -- the case change plus a
> Mode-to-Type respelling the corpus does not separately record.
> What this ADR fixed survives, relocated: the handshake-time
> fingerprint capture, the server/client asymmetry, the
> self-reported flags recorded as claims, and the
> identity-before-first-signed-deploy ordering.

## Context

A signed attestation says "this artifact was produced by this build".
Without information about *where* the build ran, that claim degrades
into "this artifact existed at some point". A verifier examining an
attestation needs to assess the trust level of the environment that
produced it: was the engine reached over a Unix socket the controller
controls, over TLS to a pinned engine, over mTLS, or over an
unauthenticated channel? Was the engine itself rootless? What version
of the engine was running?

These properties cannot be reconstructed from the artifact alone.
They have to be captured at the moment of contact and embedded into
the attestation, signed alongside the rest.

The information naturally splits along the asymmetric-identity
principle (ADR-007): the *transport* (how the controller reached the
engine) is one trust dimension, the *engine identity* (what the
engine reported about itself) is another. Both belong in the
attestation, with the asymmetry preserved.

## Decision

Every deploy attestation includes an `engine` field of type
`#EngineRecord` (defined in CUE, generated as Go). The record
contains:

- `connection_type`: `"unix"`, `"tls"`, or `"mtls"`. Captures the
  transport mode used during the deploy.
- `ca_trust_mode`: `"pinned"` (explicit CA bundle pinned by the
  controller) or `"system"` (OS trust store). Empty for Unix
  socket connections.
- `server_cert_fingerprint`: `sha256:<hex>` of the engine's leaf
  certificate. Populated for TLS and mTLS, empty for Unix sockets.
- `client_cert_fingerprint`: `sha256:<hex>` of the controller's
  client certificate. Populated for mTLS, empty otherwise.
- `rootless`: bool, the engine's self-reported rootless mode.
- `version`: the engine's self-reported version string.

The fingerprints are captured during the connection handshake (in
`internal/container`) and held on the engine instance. The deploy
package reads them via `engine.Identity()` when assembling the
attestation. The fingerprint capture is one-time per engine
connection; the attestation stamps the captured value.

The `rootless` and `version` fields are explicitly self-reported and
not independently verified. A compromised engine can lie about both.
This is acceptable because the controller's own integrity assertion
(ADR-001: API not exec; ADR-008: signing in the controller process)
does not depend on what the engine claims about itself; the
attestation simply records the claim alongside the verifiable
transport identity.

## Consequences

- A verifier reading an attestation can distinguish a deploy run
  through a pinned-CA mTLS connection from one run through a
  shared Unix socket. Both are valid; the trust they imply differs.
- Rotating the engine certificate invalidates the
  `server_cert_fingerprint` for future attestations but does not
  retroactively invalidate past ones. Previous attestations record
  the fingerprint that was current at their submission time.
- Engine identity capture requires at least one round trip
  (`/_ping` and `/info`) before the first signed deploy. The
  attestation is built after the engine identity is known; the
  deploy execution path enforces this ordering.
- The split between `server_cert_fingerprint` (server identity)
  and `client_cert_fingerprint` (client identity) preserves the
  asymmetric-identity principle in the attestation shape: a
  consumer reading the attestation cannot conflate the two.

## Principles

- Runtime is attested
- Identity is asymmetric (server fingerprint and client fingerprint
  in separate fields)
- External references are digest-pinned (fingerprints are content
  hashes of the certificates)
