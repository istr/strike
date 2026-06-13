# Strike Roadmap Status Summary

**As of 2026-06-12**, the repository is at a major inflection point: the core
verification engine is complete and in-process integration into the CLI is
underway. This document provides a snapshot of the status of all active
roadmaps.

## Status overview

| Roadmap | Status | Notes |
|---------|--------|-------|
| [ROADMAP-ADR-038](ROADMAP-ADR-038.md) | COMPLETE (+ dependency unblocked) | Protocol-mediated SSH; control-plane front; all items 1--9 complete. ADR-040 keyless unblocks remote-front exposure. |
| [ROADMAP-ADR-040](ROADMAP-ADR-040.md) | SUBSTANTIALLY COMPLETE | Instructions 1--4 done (OIDC schema, SBOM, keyless signing, OCI referrers, control-plane push). Instruction 5a (verify core) done; 5b (CLI exposure) deferred to ADR-041. |
| [ROADMAP-ADR-041](ROADMAP-ADR-041.md) | IN PROGRESS | Foundation (verify core, lane-digest sealing, identity enforcement) complete. Instructions 1--3 (CLI subcommand, lane-policy integration, predicate validation) pending. |
| [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) | H1 DONE, H2 PENDING | Stack-up and trust-anchor export complete. WebAuthn/FIDO2 (H2) remains. |

## Narrative summary

### ADR-038: Protocol-mediated SSH (COMPLETE)

Items 1--7 (control-plane front, STRIKE_PEER token, SSH server/client,
command allowlist, per-step capsule context, in-container agent removal,
synthetic container trust) are fully implemented. Items 8--9 (DoT resolver
and TLS mediator rehosting, phase-2 per-peer connection records) remain
open but are orthogonal to the verify arc.

**Dependency unblocked:** The signing key has been externalized completely
(keyless is now the exclusive path). Remote-front exposure is now unblocked
and can proceed.

### ADR-040: Control-plane SBOM and keyless attestation (SUBSTANTIALLY COMPLETE)

- **D1 (control-plane SBOM):** Fully implemented. Native SBOM cataloger in
  `internal/executor/catalog.go` emits CycloneDX and SPDX 2.3 as OCI
  referrers on the pushed digest. No external SBOM sources or buildinfo path.

- **D2 (keyless signing):** Fully implemented. Ephemeral Fulcio certificates,
  in-process DSSE signing via protobuf-specs, RFC3161 timestamping, Rekor v2
  inclusion, sigstore v0.3 bundle assembly. Every deploy statement is keyless;
  the operator holds no key material.

- **D3 (OCI referrers, layered by trust):** Fully implemented. Three separate
  in-toto statements (sealed / engine_dependent / informational) signed
  keylessly and attached as co-attached OCI referrers on the pushed digest.
  Layer boundary is now physical (separate bundles), not a convention inside
  one signature.

- **D4 (control-plane push):** Fully implemented. The control plane pushes
  via go-containerregistry; signing and referrer attachment happen on the
  registry digest. The engine no longer pushes.

- **D5 (lane-wide OIDC identity):** Fully implemented. Lane carries issuer +
  identity; Fulcio certificate cross-check validates cert issuer == declared
  issuer and cert SAN == declared identity.

- **Instruction 5 (strike verify):** Core layers (5a) fully implemented and
  tested. CLI exposure (5b) deferred to ADR-041 instruction 1 because it
  requires lane-policy binding (ADR-041 scope). The `internal/verify` package
  provides:
  - `Verifier.Verify()` end-to-end entry point
  - Independent fail-closed layers: bundle shape, trusted time, leaf chain,
    DSSE signature, Rekor inclusion
  - `ParseTrustedRoot()` for sigstore TrustedRoot bundle parsing
  - Golden-test fixtures verifying the full chain offline
  - Live tests against the sigstore-local harness

### ADR-041: The lane as verification policy (IN PROGRESS)

A new ADR that reframes verification around two use cases:
- **UC1 (consumer):** "I have an image; is its signature valid?" Explicit
  parameters: trust root, identity, issuer.
- **UC2 (operator):** "I have a lane.yaml; did the artifacts come from this
  lane under the declared identity?" The lane is the policy source.

**Foundation complete:**
- Lane digest (raw sha256 over the lane file bytes) computed at parse time
  and sealed in the attestation. Binds the lane to its artifacts version-sharp.
- Identity enforcement: the producer checks that the ambient OIDC token
  subject == lane-declared identity before Fulcio contact. Fail-closed.
- Verify core (`internal/verify`) ready to wrap with CLI and lane integration.

**Pending work (instructions 1--3):**
- Instruction 1: Lane schema extensions (`#TrustRoot`), expose `strike verify`
  subcommand with UC1 and UC2 paths.
- Instruction 2: Lane-policy integration (identity, issuer, trust root sourced
  from the lane).
- Instruction 3: Per-layer predicate validation and trust-mode gating.
- Triage: the Go engine-context `ConnectionInfo` emits `serverCertSubject`,
  `serverCertIssuer`, and `clientCertSubject`, which the closed CUE
  `#EngineConnection` does not declare. No current break (the sealed projection
  drops them via Go-field copy). Decide: promote them into `#EngineConnection`
  if they should be sealed, or document them as diagnostic-only.

### Sigstore-local test harness (H1 DONE)

The harness (Keycloak, Fulcio, Rekor v2 POSIX, TSA) runs rootless under
Podman, with all endpoints behind a Caddy TLS terminator. It exercises the
live keyless chain and provides the local trust roots for verification.

- **H1 (stack-up + trust anchors):** Complete. Services healthy, issuer
  canonical (sslip.io), trust anchors exported (Caddy root, Rekor pubkey,
  TSA certchain).
- **H2 (WebAuthn/FIDO2):** Open. Identity hardware-gated at the IdP;
  unblocks the real identity-gated producer path.

## Key completions and implications

1. **Keyless externalization is complete.** The v1 operator-key artifact
   path has been retired. Every statement signed with ephemeral Fulcio
   identities. The only durable secret is the OIDC identity. Remote-front
   exposure is unblocked.

2. **Verification engine is ready.** The `internal/verify` package is
   production-ready (core layers, golden tests, live tests). It awaits CLI
   integration and lane-policy binding.

3. **Lane as policy is foundational.** The lane_digest binding and identity
   enforcement are in place. The next phase (ADR-041 instructions 1--3)
   wraps the verify core in a lane-aware CLI subcommand.

4. **Three trust layers are now observable.** ADR-037's V (sealed) and E
   (engine-dependent) layers are now separate OCI referrers. The informational
   layer is a third referrer. Verification can gate per-layer based on trust
   mode.

## Sequencing for the next phase

ADR-041 instruction 1 is the critical path:
1. Confirm lane schema for `#TrustRoot` (digest-pinned reference + inline override)
2. (LANDED, basic path) Expose `strike verify` subcommand with UC1 (explicit
   parameters) and UC2 (lane as policy) paths
3. (LANDED, basic path) Integrate `internal/verify.Verifier` into the command
   handler

Steps 2 and 3 are wired for the basic path -- bundle read, trust-root
resolution, keyless verify per bundle, and the subject-digest check. Instruction
3 (predicate validation, lane-digest gating) is the remaining work:
- Instruction 2: Lane-policy plumbing (identity, issuer, root from lane) --
  landed for the basic path.
- Instruction 3: Predicate validation (SLSA Provenance, engine-context,
  SBOM formats; trust-mode-driven gating) and the lane-digest binding.

## References

- [ADR-041 Decision Record](ADR-041-lane-as-verification-policy.md)
- [ROADMAP-ADR-038](ROADMAP-ADR-038.md) -- Complete
- [ROADMAP-ADR-040](ROADMAP-ADR-040.md) -- Substantially complete
- [ROADMAP-ADR-041](ROADMAP-ADR-041.md) -- In progress
- [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) -- H1 done, H2 pending
