# Strike Roadmap Status Summary

**As of 2026-06-14**, the repository is at a major inflection point: the core
verification engine is complete and wrapped in a lane-aware CLI (`strike
verify`, UC1 and UC2, with per-layer predicate validation and V/E gating). This
document provides a snapshot of the status of all active roadmaps.

## Status overview

| Roadmap | Status | Notes |
|---------|--------|-------|
| [ROADMAP-ADR-038](ROADMAP-ADR-038.md) | PARTIAL (1--7 done; 8--9 remain) | Protocol-mediated SSH; control-plane front. Items 8 (DoT resolver + TLS mediator rehosting onto the front) and 9 (SSH-mediated per-connection records) remain. Remote-front exposure unblocked by ADR-040 keyless. |
| [ROADMAP-ADR-040](ROADMAP-ADR-040.md) | SUBSTANTIALLY COMPLETE | Instructions 1--4 done (OIDC schema, SBOM, keyless signing, OCI referrers, control-plane push). Instruction 5a (verify core) done; 5b (CLI exposure) landed via ADR-041. |
| [ROADMAP-ADR-041](ROADMAP-ADR-041.md) | SUBSTANTIALLY COMPLETE | Foundation plus instructions 1--3 (CLI subcommand, lane-policy integration, predicate validation and V/E gating) landed. Genuine residual: trust-root auto-import from OCI referrers (currently fail-closed). |
| [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) | H1 DONE, H2 PENDING | Stack-up and trust-anchor export complete. WebAuthn/FIDO2 (H2) remains. |
| [ROADMAP-cue-spec-review](ROADMAP-cue-spec-review.md) | OPEN | Post-formalization D-arcs. Landed: A, D-A, D-C, D-D formalization, D-E, C-5, B-1, C-3. Open: D-B+D-G (canonical-time + principle), D-D field-add, D-F (B-2--B-9). |

## Narrative summary

### ADR-038: Protocol-mediated SSH (PARTIAL)

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
  tested. CLI exposure (5b) landed via ADR-041 instructions 1--3 (lane-policy
  binding, predicate validation, V/E trust-mode gating). The `internal/verify`
  package provides:
  - `Verifier.Verify()` end-to-end entry point
  - Independent fail-closed layers: bundle shape, trusted time, leaf chain,
    DSSE signature, Rekor inclusion
  - `ParseTrustedRoot()` for sigstore TrustedRoot bundle parsing
  - Golden-test fixtures verifying the full chain offline
  - Live tests against the sigstore-local harness

### ADR-041: The lane as verification policy (SUBSTANTIALLY COMPLETE)

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

**Landed (instructions 1--3):**
- Instruction 1: Lane schema extensions (`#TrustRoot`), `strike verify`
  subcommand with UC1 and UC2 paths.
- Instruction 2: Lane-policy integration (identity, issuer, trust root sourced
  from the lane).
- Instruction 3: Per-layer predicate validation and V/E trust-mode gating
  (`--no-engine-trust`), over the enriched goldens (instruction 3a).

**Genuine residual (this roadmap):** trust-root auto-import from OCI referrers.
When the lane declares no trust root and no `--trust-root` is passed, verify is
fail-closed (`internal/verify.ErrNoTrustRoot`); deriving the trust root from the
image's referrers is a future enhancement, not a regression.

**Tracked elsewhere (not this roadmap):** base-SBOM signature verification lives
in ROADMAP-ADR-040 (instruction 2c); the engine-cert subject/issuer field-add
lives in ROADMAP-cue-spec-review (D-D field-add). The v1-verifier teardown is
complete -- the keyed path is gone from non-test code.

### Sigstore-local test harness (H1 DONE)

The harness (Keycloak, Fulcio, Rekor v2 POSIX, TSA) runs rootless under
Podman, with all endpoints behind a Caddy TLS terminator. It exercises the
live keyless chain and provides the local trust roots for verification.

- **H1 (stack-up + trust anchors):** Complete. Services healthy, issuer
  canonical (sslip.io), trust anchors exported (Caddy root, Rekor pubkey,
  TSA certchain).
- **H2 (WebAuthn/FIDO2):** Open. Identity hardware-gated at the IdP;
  unblocks the real identity-gated producer path.

### CUE spec review (post-formalization D-arcs, OPEN)

Tracked in [ROADMAP-cue-spec-review](ROADMAP-cue-spec-review.md). The arcs
derived from `RETROSPECTIVE-cue-spec-review.md` are partly landed at `8721d0ff`:
cluster A (docs), D-A (keyed signing + Rekor v1 removal, ADR-043), D-C
(`engineMetadata` -> informational), the D-D trust-boundary formalization, D-E
(Bundle/DSSE in CUE), C-5, B-1, and C-3. Three arcs remain: D-B+D-G
(canonical-time correction to RFC3161 TSA plus the "Meaning is single-sourced"
principle and the aim-sentence qualification, operator-owned), the D-D field-add
(engine-cert subject/issuer into `#EngineConnection` at layer V), and the D-F
queue (schema-naming findings B-2--B-9, one instruction each). The deferred set
(base-SBOM signature verification, engine hardening, DNS centralization, full
TLS demux, the osv-scalibr PR, and the `TestPackSBOM/deterministic_sbom` flake)
is carried in that roadmap.

## Key completions and implications

1. **Keyless externalization is complete.** The v1 operator-key artifact
   path has been retired. Every statement signed with ephemeral Fulcio
   identities. The only durable secret is the OIDC identity. Remote-front
   exposure is unblocked.

2. **Verification engine is wired into the CLI.** The `internal/verify` package
   (core layers, golden tests, live tests) is now driven by the `strike verify`
   subcommand with lane-policy binding (UC1 and UC2).

3. **Lane as policy is realized.** The lane_digest binding and identity
   enforcement are in place, and ADR-041 instructions 1--3 wrap the verify core
   in a lane-aware CLI subcommand that gates on the lane digest under UC2.

4. **Three trust layers are now observable.** ADR-037's V (sealed) and E
   (engine-dependent) layers are now separate OCI referrers. The informational
   layer is a third referrer. Verification can gate per-layer based on trust
   mode.

## Execution order (cross-roadmap)

This is the single source for the cross-roadmap execution order. It groups the
open work from every roadmap into phases by dependency and risk; each item
points to the roadmap that owns its detail. Re-sort this section as priorities
change -- the per-roadmap detail stays in the owning roadmaps, only the ordering
lives here.

The only hard cross-roadmap dependency is the engine/transport chain in
Phase 3: the D-D field-add records the engine-cert fields at Layer V and is the
precursor the engine-hardening arc builds on, which in turn gates the
front-rehosting and the remote-engine horizon. Everything else is independent
and parallelizable.

**Phase 0 -- roadmap truth and the order itself (docs only).** Reconcile the
stale subsections so planning state is accurate, rehome cross-roadmap references
to a single owner, and install this section. (This phase.)

**Phase 1 -- contract hygiene (low risk, parallelizable).**
- D-B+D-G: canonical-time correction (RFC3161 TSA) plus the "Meaning is
  single-sourced" principle and the aim-sentence qualification. Operator-owned,
  docs only, first. (ROADMAP-cue-spec-review)
- D-F B-2..B-9: schema-naming findings, one instruction each, order B-2, B-3,
  B-6, B-7 -> B-4, B-5 -> B-8, B-9. (ROADMAP-cue-spec-review)
- D-D field-add: engine-cert subject/issuer into `#EngineConnection` at Layer V;
  CUE-first gate. Lands here and unlocks Phase 3. (ROADMAP-cue-spec-review)

**Phase 2 -- verification completeness.**
- Base-SBOM signature verification (2c), unblocked by the verify core.
  (ROADMAP-ADR-040)
- cosign independent-verify conformance check: the "offline-verifiable without
  contacting strike" promise under independent tooling.
  (ROADMAP-sigstore-test-harness)
- Trust-root auto-import from OCI referrers, lifting the current fail-closed
  posture. (ROADMAP-ADR-041)
- H2 WebAuthn/FIDO2: schedule when the hardware-gated identity path is needed.
  (ROADMAP-sigstore-test-harness)

**Phase 3 -- engine/transport hardening (gated on the Phase 1 D-D field-add).**
- Engine hardening / transport-unification, flipping `hardenedByDeclaration` to
  true. (ROADMAP-cue-spec-review, deferred set)
- ADR-038 item 8: rehost the DoT resolver and TLS mediator onto the front,
  together with DNS centralization (same surface).
  (ROADMAP-ADR-038; DNS centralization in ROADMAP-cue-spec-review)
- ADR-038 item 9: SSH-mediated per-connection observed records (collection side
  already landed). (ROADMAP-ADR-038)

**Phase 4 -- horizon (deferred, blocked, or organic).**
- Full TLS single-port demux: blocked on L3 source-IP preservation, which pasta
  splice-only cannot provide; remote-engine / routed-netns horizon.
  (ROADMAP-cue-spec-review, deferred set)
- Upstream osv-scalibr PR: organic ecosystem work, no longer needed for strike.
  (ROADMAP-cue-spec-review, deferred set)
- `TestPackSBOM/deterministic_sbom` flake, the ARCHITECTURE.md threat-row
  judgment, and the `SignedArtifact` rename. (ROADMAP-cue-spec-review,
  deferred set)

## References

- [ADR-041 Decision Record](ADR-041-lane-as-verification-policy.md)
- [ROADMAP-ADR-038](ROADMAP-ADR-038.md) -- Complete
- [ROADMAP-ADR-040](ROADMAP-ADR-040.md) -- Substantially complete
- [ROADMAP-ADR-041](ROADMAP-ADR-041.md) -- Substantially complete
- [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) -- H1 done, H2 pending
- [ROADMAP-cue-spec-review](ROADMAP-cue-spec-review.md) -- Open (D-B+D-G, D-D field-add, D-F: B-2--B-9)
