# Strike Roadmap Status Summary

**As of 2026-06-17**, the repository is at a major inflection point: the core
verification engine is complete and wrapped in a lane-aware CLI (`strike
verify`, UC1 and UC2, with per-layer predicate validation and V/E gating). This
document provides a snapshot of the status of all active roadmaps.

## Status overview

| Roadmap | Status | Notes |
|---------|--------|-------|
| [ROADMAP-ADR-038](ROADMAP-ADR-038.md) | PARTIAL (1--7 done; 8--9 remain) | Protocol-mediated SSH; control-plane front. Items 8 (DoT resolver + TLS mediator rehosting onto the front) and 9 (SSH-mediated per-connection records) remain. Remote-front exposure unblocked by ADR-040 keyless. |
| [ROADMAP-ADR-040](ROADMAP-ADR-040.md) | SUBSTANTIALLY COMPLETE | Instructions 1--4 done (OIDC schema, SBOM, keyless signing, OCI referrers, control-plane push). Instruction 5a (verify core) done; 5b (CLI exposure) landed via ADR-041. Instruction 2c (base-SBOM signature verification) landed; live e2e against the harness remains. |
| [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) | H1 DONE, H2 PENDING | Stack-up and trust-anchor export complete. WebAuthn/FIDO2 (H2) remains. |
| [ROADMAP-ADR-046](ROADMAP-ADR-046.md) | PLANNED | Output model (ADR-046): a step with output produces exactly one canonical digest-pinned image. Owns the former execution-order item 7b (imageFromStep rebuild + D1--D4) plus the producer one-image fix and consumer pull-by-digest. ADR-045/7a landed as the predecessor. |
| ROADMAP-cue-spec-review (retired) | RETIRED | All review arcs landed (A, D-A, D-C, D-D, D-E, C-5, B-1, C-3, D-B+D-G, D-F B-1..B-9); the deferred backlog moved into the execution order below. History in git. |

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

- **Instruction 2c (base-SBOM signature verification):** Landed. The registry
  fetch path (`internal/registry` `FetchBaseSBOMReferrers`, 2c-i), the lane
  build guard primitives (`internal/lane` `PackBaseRefs` /
  `validateBaseSBOMTrustAnchor`, 2c-ii-a), and producer-side verification in
  `internal/deploy` calling `internal/verify` directly (2c-ii-b) are all
  implemented. Verified base SBOMs are recorded in SLSA `resolvedDependencies`
  by referrer-manifest digest with a fail-closed three-way contract (declared
  signer / SBOM predicate type / base-digest subject binding). The live e2e
  against the harness is the only residual.

### Sigstore-local test harness (H1 DONE)

The harness (Keycloak, Fulcio, Rekor v2 POSIX, TSA) runs rootless under
Podman, with all endpoints behind a Caddy TLS terminator. It exercises the
live keyless chain and provides the local trust roots for verification.

- **H1 (stack-up + trust anchors):** Complete. Services healthy, issuer
  canonical (sslip.io), trust anchors exported (Caddy root, Rekor pubkey,
  TSA certchain).
- **H2 (WebAuthn/FIDO2):** Open. Identity hardware-gated at the IdP;
  unblocks the real identity-gated producer path.

### CUE spec review (post-formalization D-arcs, COMPLETE -- roadmap retired)

Tracked in the now-retired ROADMAP-cue-spec-review (history in git; its deferred
backlog migrated into the execution order below). The arcs derived from
`RETROSPECTIVE-cue-spec-review.md` all landed:
cluster A (docs), D-A (keyed signing + Rekor v1 removal, ADR-043), D-C
(`engineMetadata` -> informational), the D-D trust-boundary formalization, D-E
(Bundle/DSSE in CUE), C-5, B-1, C-3, and D-B+D-G (canonical-time correction to
RFC3161 TSA plus the "Meaning is single-sourced" principle and the aim-sentence
qualification). The D-F queue is now complete (B-1..B-9 landed or wontfix; B-8
typed the path fields, B-9 renamed `clientId` -> `audience` and reordered the
`forceRun` default to default-first, recording the `#SignerIdentity` dedup and
the `trustRootRef` `@go` symmetry as wontfix). One arc remains: the D-D
field-add (engine-cert subject/issuer into `#EngineConnection` at layer V). The
B-5 follow-ons (the
`...Name` -> `...ID` Go rename and the producer-ref runtime encoding) have
landed; the output-model arc (the `imageFromStep` rebuild plus the producer one-image fix and consumer pull-by-digest) is now owned by [ROADMAP-ADR-046](ROADMAP-ADR-046.md) (ADR-046 ratified; ADR-045/7a landed as its predecessor). The deferred set
(base-SBOM signature verification, engine hardening, DNS centralization, full
TLS demux, and the osv-scalibr PR) is carried in that roadmap.

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

5. **Deterministic tier assignment and foundation package landed.** ADR-044
   formalizes the tier-assignment criterion. The DSSE/in-toto wire primitives
   (`PAEEncode` / `PayloadType` / `MediaType`) live in a role-neutral foundation
   package `internal/bundle`; `verify` no longer depends on `deploy`; foundation
   forbids any internal dependency and orchestration forbids intra-tier edges.
   ADR-044 was then sharpened to forbid satisfying a forbidden tier edge by
   composition-root injection; `internal/verify` is reclassified to the services
   tier and `internal/deploy` imports it as a legal downward static edge (the
   earlier cmd-wired injection seam is gone).

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

**Phase 1 -- contract hygiene (low risk, parallelizable).**
- D-B+D-G (LANDED): canonical-time correction (RFC3161 TSA) plus the "Meaning is
  single-sourced" principle and the aim-sentence qualification. Operator-owned,
  docs only, first. (ROADMAP-cue-spec-review)
- D-F B-3 (LANDED): `#Subject` reuses `#ResourceDescriptor` via refinement; Go mirror unchanged.
- D-F B-2 (LANDED): `gitCommit` width widened to 40-or-64-hex.
- D-F B-6 (LANDED): `#TLSTrust` discriminator `mode` -> `type` + enum camelCasing
  (`certFingerprint` / `caBundle`); hand-mirrored Go and golden bundles moved in
  lockstep. (ROADMAP-cue-spec-review)
- D-F B-7 (LANDED): deploy state-capture config renamed `attestation` ->
  `recording` (`#StateRecording` / `#CaptureSet` / `#Capture`); the
  cryptographic-attestation family unchanged. (ROADMAP-cue-spec-review)
- D-F B-4 (LANDED): `id` / `name` normalization (B-4a/b/c).
  (ROADMAP-cue-spec-review)
- D-F B-5 (LANDED): producer refs unified on `#OutputRef` (`232bece`); the
  runtime-encoding follow-on landed too (`ae12db3`). (ROADMAP-cue-spec-review)
- D-F B-8 (LANDED): path-type consolidation -- `#ImageConfig.workdir` typed
  `#AbsPath`, dead `#Artifact.localPath` removed, opaque path-like fields
  commented (`5dd7ea1`). (ROADMAP-cue-spec-review)
- D-F B-9 (LANDED): `clientId` -> `audience` and `forceRun` default-first; the
  `#SignerIdentity` dedup and `trustRootRef` `@go` symmetry recorded wontfix.
  (ROADMAP-cue-spec-review)
- D-D field-add (LANDED): re-modeled `#EngineConnection` as a discriminated
  union in transport.cue (engine-cert subject/issuer sealed at Layer V,
  `caTrustType`); the cue-spec-review arcs are complete and Phase 3 is
  unblocked (`8694653`). (ROADMAP-cue-spec-review)

The completed contract-hygiene work is Phase 1 above. All remaining open work,
across every roadmap, is the single ratified sequence below (risk / effort /
dependency-depth weighed). Steps 1-2 are near-zero-risk fill that can land
anytime; 3-7 are the verification and independent-schema arcs; 8-11 are the
engine/transport cluster on the now-landed D-D foundation; the rest is parked.

**Active execution order (ratified).**

7a. imageFrom execution hardening (V) -- LANDS FIRST, ADR-045. On the current
   `imageFrom {step, output}` schema, run every step's base image only by its
   CP-verified content digest (`<locator>@sha256:<digest>`) and remove the
   execute-by-tag path. The CP already verifies controller == engine manifest
   digest at wrap time (`WrapImageArchiveAsImage`), so the digest to pin is in
   hand; the transport mechanism -- run the local-store image by digest (alpha)
   vs a CP content-addressed registry roundtrip (beta) -- is settled by a
   measurement spike before byte-exact authoring. The canonical engine tag
   `localhost/strike/<lane-id>/<step-id>:<spec_hash>` stays a cache-existence
   lookup key, never the execution anchor. Reuses existing components; closes the
   false layer-V assurance recorded in ADR-045. Live e2e against the harness.
   Decision: D3.
7b. Output model (ADR-046) -- the `imageFromStep` rebuild, the producer
   one-image fix, and the consumer pull-by-digest now live in
   [ROADMAP-ADR-046](ROADMAP-ADR-046.md); decisions D1--D8 are recorded there.
   Settle the schema before the engine cluster.
8. Observed-TLS identity consolidation -- ENGINE-CLUSTER LEAD. The observed TLS
   server identity appears in three diverging shapes: `#ObservedTLS` (peers;
   type + fingerprint), `#ResolverRecord` (resolver; fingerprint + tlsVersion /
   cipherSuite / serverName), and the engine union's `#EngineServerTLS`
   (fingerprint + subject + issuer + caTrustType). Decide here whether to factor
   one shared observed-TLS-server-identity type in transport.cue ("Meaning is
   single-sourced") or keep them role-distinct, so the hardening matching (10)
   is written once against a settled shape. Golden-affecting (resolver sealed).
   (migrated from cue-spec-review)
9. ADR-038 item 9: SSH-mediated per-connection observed records -- the
   collection side (`collectObservedPeers` / `ingestRecords`) already landed;
   the SSH mediator must emit per-connection records (host-key fingerprint,
   negotiated algorithms, allowlisted command) into the capsule records, as the
   TLS and DoT mediators already do. Self-contained; completes observed-peer
   coverage. Parallelizable with 8. (ROADMAP-ADR-038)
10. Engine hardening / transport-unification -- flips the engine
    `hardenedByDeclaration` to true. DEEP: there is no declared engine identity
    in the lane schema yet, so this creates the declaration side plus the
    matching of the observed identity (sealed by D-D) against the declared one.
    Highest risk / effort / dependency-depth; lands on the 8 + 9 foundation.
    (ROADMAP-ADR-038; detail migrated from cue-spec-review)
11. ADR-038 item 8: rehost the DoT resolver and TLS mediator onto the front,
    with DNS centralization (same surface) -- independent of the trust flip but
    the same front surface; high effort. Last substantive arc; can run in
    parallel under a separate operator since both touch the front.
    (ROADMAP-ADR-038; DNS centralization migrated from cue-spec-review)

**Parked -- blocked, organic, or schedule-when-needed.**
- Full TLS single-port demux -- blocked on L3 source-IP preservation, which
  pasta splice-only cannot provide; remote-engine / routed-netns horizon.
  (migrated from cue-spec-review)
- Upstream osv-scalibr PR -- organic ecosystem work, no longer needed for
  strike; decouples disk-image extractors from the filesystem extractor import
  path. (migrated from cue-spec-review)
- H2 WebAuthn/FIDO2 -- schedule when the hardware-gated identity path is needed.
  (ROADMAP-sigstore-test-harness)

## References

- [ROADMAP-ADR-038](ROADMAP-ADR-038.md) -- PARTIAL (items 8-9 remain)
- [ROADMAP-ADR-040](ROADMAP-ADR-040.md) -- Substantially complete
- [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) -- H1 done, H2 pending
- ROADMAP-cue-spec-review -- RETIRED (all arcs landed; deferred backlog migrated into the execution order; history in git)
