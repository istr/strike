# ADR-029: Peers are container-egress contracts; the OCI peer type is removed

## Status

Accepted. Refines [ADR-022](ADR-022-network-opt-in-as-peer-list.md)
(which introduced three peer types) and is consistent with
[ADR-028](ADR-028-step-container-egress-mediation.md) (which already
routes container-initiated OCI traffic as HTTPS).

## Context

ADR-022 introduced a typed peer list with three variants: HTTPS,
SSH, and OCI, "each with the appropriate trust anchor (cert
fingerprint or CA bundle for HTTPS, known_hosts for SSH, image
digest for OCI)." Phase-2 enforcement (ADR-028) implemented
per-peer container egress for HTTPS (TLS mediation) and continued
the existing SSH handling (known_hosts, agent proxy).

Implementing the enforcement story surfaced that the OCI peer
variant carries no content the other mechanisms do not already
provide. A concrete lane made this visible: a step declared an OCI
peer for its base-image registry and ran `npm ci`, which needs the
npm registry. The OCI peer was both (a) redundant with the
digest-pinned `image:` reference and (b) the trigger for a
network-mode bug (any non-empty peer list yielded bridge
networking, so the step reached the npm registry undeclared).

## Decision

Peers are container-egress trust contracts, exclusively. Each peer
declares a destination the step container may reach during
execution, with the trust anchor strike uses to verify that
destination. Two protocols are supported: HTTPS (mediated) and SSH
(known_hosts + agent proxy).

The OCI peer type is removed. Its two possible meanings are both
covered without it:

- A step's own image is pulled controller-side and verified
  against its pinned digest (ADR-028 establishes the pull is not
  container traffic). The digest is the integrity anchor; the
  registry in the reference is a location. No peer declaration adds
  integrity, because an attacker controlling the named registry
  cannot substitute a different image without breaking the
  SHA-256 digest.
- A container that itself performs registry operations
  (docker/buildah/podman inside the step) reaches the registry
  over HTTPS and declares it as an HTTPS peer. ADR-028 already
  specifies this: container-initiated OCI traffic "flows through
  Component 2's TLS mediation pattern like any other HTTPS peer."

Declaring `type: oci` is now a parse error.

## Consequences

- Lanes that declared an OCI peer must remove it. If it was the
  step's only peer, the step now runs with `--network=none` (its
  image is local after the controller-side pull). If the container
  needs network access, the lane must declare the actual HTTPS (or
  SSH) destinations -- which is the point of "Peers are declared".
- The peer discriminated union loses a branch; the schema, the Go
  types, the JSON dispatch, and the attestation re-export drop the
  OCI variant.
- OCI *provenance* records (the provenance of a consumed upstream
  OCI artifact) are unaffected; they are a distinct concept from
  the OCI *peer* type.

## Alternatives considered

- **Keep the OCI peer, make it egress-irrelevant.** Rejected: a
  type that exists but means nothing is a trap; lane authors
  declare it expecting an effect.
- **Repurpose the OCI peer as a controller-pull-registry
  allowlist** ("base images may be pulled only from these
  registries"). Rejected as a *peer* type: it is a controller-side
  source restriction, not a container-egress contract, and it is
  integrity-redundant given digest pinning. If wanted later, it
  belongs as a distinct lane-level field, not as a peer. Out of
  scope.

## Relationship to ADR-022

ADR-022's enumeration of three peer types is superseded in part:
the OCI variant is withdrawn. ADR-022's core decision -- that
network interaction is a typed trust contract rather than a boolean
-- stands, and is strengthened: every peer is now a
container-egress contract with a concrete enforcement story (HTTPS
mediation, SSH known_hosts/agent), with no declaratory-only
variant remaining.
