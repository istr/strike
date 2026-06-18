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
| [ROADMAP-ADR-041](ROADMAP-ADR-041.md) | COMPLETE | Foundation plus instructions 1--3 (CLI subcommand, lane-policy integration, predicate validation and V/E gating) landed; the CLI trust-root override is a digest-pinned image ref (`--trust-root-ref`, `669eca89`), so the verify path reads no host-local file. No residual. |
| [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) | H1 DONE, H2 PENDING | Stack-up and trust-anchor export complete. WebAuthn/FIDO2 (H2) remains. |
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

### ADR-041: The lane as verification policy (COMPLETE)

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

**No residual -- this roadmap is complete.** The trust root is sourced only from
lane bytes (`keyless.trustRoot`) or a digest-pinned OCI image: the lane's
`keyless.trustRootRef`, or the `--trust-root-ref` CLI override (`669eca89`). The
verify path reads no host-local file. When the lane declares no trust root and no
`--trust-root-ref` is passed, fail-closed (`internal/verify.ErrNoTrustRoot`) is
the intended terminal, not a gap: the anchor must be operator-chosen, never
derived from the verified artifact (ADR-041 Principles).

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
landed; only the `imageFromStep` rebuild remains parked. The deferred set
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

1. ARCHITECTURE.md threat-row judgment (LANDED) -- "Signing key exfiltrated"
   corrected for keyless model (ADR-043); no persistent key so key rotation
   does not apply; Rekor CT logs every signature. (`560a60f`)
2. `ArtifactRecord` rename (LANDED) -- post-keyless the old `SignedArtifact`
   name was a digest+SBOM misnomer; a pure Go rename, wire-neutral, no golden.
   (`148c1f5`)
3. cosign independent-verify conformance, CT-gated (LANDED) -- validated the
   "offline-verifiable without contacting strike" promise under independent
   tooling (cosign), as the regression baseline for the verification work. The
   feasibility spike (GO) found cosign enforces a >= 1 SCT threshold with no
   non-insecure bypass, so the harness gained a CT log first. Landed in four
   commits: 3a -- harness CT enablement (TesseraCT POSIX; Fulcio on fileca +
   ct-log-url; no Trillian) (`41661d4`), TLS-fronted behind Caddy (`658fb3a`);
   3b -- ctlogs entry in goldenTrustedRoot + golden regen against the CT-enabled
   harness (`7546fca`); 3c -- the flag-clean `make conformance` target (no
   --insecure-ignore-sct), gating exit on the V layer (`386dba2`).
   (ROADMAP-sigstore-test-harness)
   Deferred follow-ons (separate ratification), both sequenced after this arc,
   detail in ROADMAP-sigstore-test-harness H3: (1) production verify-path --
   strike's own verify ignores the embedded SCT; whether it should enforce it
   for posture symmetry with cosign is its own item. (2) full cosign
   compatibility -- liveTrustRoot does not yet carry the ctlogs entry (only the
   golden generator does); pulling it in is the remaining live-path step.
4. Base-SBOM signature verification (2c) (LANDED) -- cosign fixture and
   strike-verify smoke gate (`e1721cf3`); `internal/registry`
   `FetchBaseSBOMReferrers` artifactType-filter path, no config re-check
   (2c-i, `0e4b9a8e`); `internal/lane` `PackBaseRefs` /
   `validateBaseSBOMTrustAnchor` build guard (2c-ii-a, `c3b079ae`);
   producer-side base-SBOM verification in `internal/deploy` calling
   `internal/verify` directly, recording verified base SBOMs in
   `resolvedDependencies` by referrer digest with a fail-closed three-way
   contract (2c-ii-b, `bc35f1e8`; the cmd-wired injection seam it originally
   shipped with was removed once `internal/verify` was placed at its
   criterion-correct services tier -- see the ADR-044 arc below).
   Deferred: live e2e against the harness (ROADMAP-ADR-040). (ROADMAP-ADR-040)
4x. ADR-044 / `internal/bundle` / arch-lint arc (LANDED, mid-2c) --
   deterministic tier-assignment criterion formalized in ADR-044 (`c214dae5`);
   role-neutral DSSE/in-toto wire primitives (`PAEEncode` / `PayloadType` /
   `MediaType`) extracted into the `internal/bundle` foundation package;
   `verify -> deploy` import edge severed; `.go-arch-lint.yml` tightened
   (foundation forbids any internal dependency; orchestration forbids intra-tier
   edges); deploy/verify coupling initially expressed as the cmd-wired injection
   seam above rather than a direct import (`ec2d4ed`). That seam was a
   circumvention, not a resolution: ADR-044 was subsequently sharpened to forbid
   satisfying a forbidden tier edge by composition-root injection, `internal/verify`
   was reclassified to its criterion-correct services tier, and `internal/deploy`
   now imports it as a legal downward static edge (the seam --
   `VerifyBaseSBOMFunc`, the `Deployer` field, the cmd closure -- is gone). No
   owning roadmap beyond ADR-044 itself.
5. Trust-root override as a digest-pinned image ref (LANDED, `669eca89`) -- the
   CLI override moved from a host-local file to a `--trust-root-ref` image,
   resolved through `registry.FetchTrustRoot` like the lane's `trustRootRef`, so
   the verify path reads no host-local file. Fail-closed `ErrNoTrustRoot` when no
   anchor is declared is the intended terminal, not a residual. This completes
   ADR-041; the earlier "auto-import from referrers" framing was superseded -- the
   anchor is never sourced from the verified artifact. (ROADMAP-ADR-041)
6. Artifact / secret / step map-key id normalization (LANDED). Retyped the
   four structured map keys -- `#Lane.secrets`, `#DeploySpec.artifacts`, and
   the deploy `peers` / `peerAttribution` maps (attestation.cue, predicate.cue)
   -- from `[Name=string]` / `[Step=string]` to `[ID=#Identifier]`. Measured
   (closedness/neutrality spike): rejection is load-bearing, and the change is
   wire-neutral at the Go-API level and golden-neutral -- the earlier "wire
   change, golden-affecting, cold-harness regen" framing was wrong; no regen
   was needed. The two gengotyped lane maps carry a
   `@go(...,type=map[string]T)` outer-field override (a tightened key pattern
   is not expressible as a Go map key, so gengotypes would otherwise emit
   `struct{}`). `[Endpoint=string]` (host:port) and `[Path=string]`
   (configFiles) stay free-form; stricter typing for those is planned
   separately. Deferred: the deploy-package maps are not gengotyped today and
   carry no `@go` override; when deploy gengotypes is unblocked, the same
   override is required on `peers` (`map[string][]lane.Peer`,
   full-import-path form), `peerAttribution` (`map[string][]string`), and
   `artifacts` (`map[string]ArtifactRecord`) -- fold into that arc, do not add
   speculatively. Note: `#Lane.secrets` exports an open JSON Schema
   (patternProperties only) while `artifacts` exports closed; strike validates
   CUE-natively so both reject bad keys in-process, and the secrets contract is
   revisited separately. (migrated from cue-spec-review)
7. `imageFromStep` rebuild -- `#Step.imageFrom` (`#ImageFrom {step, output}`)
   mis-models multi-stage base images. Correct model: a step's base image is
   `image` (digest-pinned external) XOR a previous step's produced image,
   referenced by step id alone. Rebuild as `imageFromStep: #Identifier` (drop
   `output`), keep the `image` / `imageFrom` / `pack` / `deploy` XOR (enforced
   in `parse.go`), and have the resolver pull the step's canonical engine image
   `localhost/strike/<lane-id>/<step-id>`. Independent; not golden-affecting
   (the golden lane is single-stage). Settle the schema before the engine
   cluster. (migrated from cue-spec-review)
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

- [ADR-041 Decision Record](ADR-041-lane-as-verification-policy.md)
- [ROADMAP-ADR-038](ROADMAP-ADR-038.md) -- PARTIAL (items 8-9 remain)
- [ROADMAP-ADR-040](ROADMAP-ADR-040.md) -- Substantially complete
- [ROADMAP-ADR-041](ROADMAP-ADR-041.md) -- Substantially complete
- [ROADMAP-sigstore-test-harness](ROADMAP-sigstore-test-harness.md) -- H1 done, H2 pending
- ROADMAP-cue-spec-review -- RETIRED (all arcs landed; deferred backlog migrated into the execution order; history in git)
