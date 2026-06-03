# ADR-040 Implementation Roadmap

## Status: IN PROGRESS (instruction 1 done; instructions 2--5 remain)

ADR-040 is Accepted and plumbed: the decision record is at
`docs/ADR-040-control-plane-sbom-and-keyless-attestation.md`, registered in
`docs/ADR-INDEX.md` by number and by principle, with the partial-supersession
back-reference to ADR-019 and the extension note to ADR-037 in place.

D5 is done (instruction 1a) and the D3 output predicate types are defined
(instruction 1b). The remaining decisions (D1, D2, D3 packaging, D4) are
not yet implemented in code. This roadmap decomposes that work into the
established numbered instruction-file sequence.

## What has landed

- **ADR-040 plumbing.** Decision record placed, indexed, cross-referenced.
  Status flipped to Accepted.
- **Instruction 1a -- lane-wide OIDC identity (D5).** `#OIDCConfig` added to
  `specs/lane.cue` with generated Go type. The lane carries the declared
  signing identity (issuer + identity) that ADR-040 D5 cross-checks against
  the Fulcio certificate.
- **Instruction 1b -- output predicate types (D3).** `specs/predicate.cue`
  defines the two standard-ecosystem attestation shapes: a sealed (Layer V)
  in-toto Statement v1 wrapping SLSA Provenance v1
  (`#SLSAProvenanceStatement`), and an engine_dependent (Layer E) statement
  wrapping a strike-defined engine-context predicate
  (`#EngineContextStatement`). Hand-written Go types in
  `internal/deploy/predicate.go`, validated against the embedded CUE schema.
  The internal `#Attestation` collect-model is unchanged; projection into
  these output shapes is instruction 3.
- **Decision basis: two spikes (both complete).**
  - scalibr import-surface spike (PARTIAL result): the heavy clusters
    (container-runtime, grpc, sqlite, vuln, TUI, cloud crypto, resolution)
    prune under `fs.FS` plus avoiding the `extractor/filesystem/list`
    aggregator. The disk-image cluster (go-diskfs / ext4 / ntfs) remains via
    the unconditional `extractor/filesystem -> embeddedfs/common` import; the
    D1 thin walker handles it, and a parallel upstream PR decouples it.
  - keyless import-surface spike (COMPOSED-COVERS result): the composed set
    (sigstore-go/pkg/sign + sigstore/pkg/oauthflow + go-containerregistry)
    compiles the full chain (OIDC -> Fulcio -> DSSE -> Rekor v2 -> referrer
    attach) at roughly one third the binary size of cosign-as-a-library and
    without the cloud-KMS provider clusters. Decision: compose.
- **Verify foundation (from ADR-037).** The `internal/verify` package
  (DSSE envelope parsing, payload-type guard, ECDSA P-256 signature
  verification over PAE) exists and is the base instruction 5 builds on. It
  was written for the operator-held-key path and is reoriented, not
  discarded, under keyless (see instruction 5).

## What is NOT yet implemented

Grounded against the current snapshot.

### D1 -- control-plane SBOM over the sealed artifact

The buildinfo path is intact. `GenerateSBOM` and the `debug/buildinfo`
import live in `internal/executor/sbom.go`; there is no osv-scalibr import,
no `fs.FS` walker, and no SPDX output anywhere in the tree. The SBOM today
describes the packed Go binary, not the artifact -- the class of the
`read build info from "": no such file` crash. Removed and replaced in
instruction 2.

### D2 -- keyless signing, in-process

No sigstore / Fulcio / oauthflow / rekor-tiles import exists; the only
`dev.sigstore.cosign/*` references are the existing cosign-tag referrer
annotations on the registry side, not a signing path. Signing remains
operator-key / ECDSA P-256 DSSE. Replaced by the composed keyless chain in
instruction 3.

### D3 -- cosign-compatible OCI referrers, layered by trust

The three layers (sealed V / engine_dependent E / informational) exist as
predicate sections inside one attestation (ADR-037). ADR-040 D3 makes the
V / E boundary physical: each layer becomes a separate, co-attached referrer
(sealed = standard SLSA Provenance v1; engine_dependent = a strike-defined
predicate type `https://istr.dev/strike/predicates/engine-context/v1`;
informational = signed byproducts that never gate). The output predicate
types are defined (instruction 1b: `specs/predicate.cue`,
`internal/deploy/predicate.go`). What remains: the projection from the
internal `#Attestation` into these shapes, signing each as its own
attestation (instruction 3), and per-layer verification exit
(instruction 5).

### D4 -- the control plane owns the registry push

No `remote.Write` push path exists in production code. The control plane
does not yet push; signing-and-attach therefore cannot yet run on the
registry digest. Landed in instruction 4.

### D5 -- lane-wide OIDC identity, pinned -- DONE (instruction 1a)

`#OIDCConfig` added to `specs/lane.cue` with generated Go type (instruction
1a). The declared identity (issuer + identity) is carried into the sealed
provenance's `externalParameters.oidc` (instruction 1b). The Fulcio
certificate cross-check (cert issuer == declared issuer, cert SAN ==
declared identity) is instruction 5.

## Instruction-file sequence

CUE-first, then implementation. Each item is its own numbered instruction
file under the established conventions (Goal, Why, Confirmation Gate,
Sequence, What NOT to do, Anti-initiative clause, Acceptance criteria,
copy-paste-ready Commit message). Each verifies in its acceptance criteria
that `docs/ADR-INDEX.md` reflects ADR-040. None of these files is written
until its design fork is ratified; instruction 1 (schema) is written and
landed before any implementation instruction.

### 1. CUE schema (D5 + the D3 predicate shapes) -- DONE

**1a (D5).** Added `#OIDCConfig` to `specs/lane.cue` with generated Go type.

**1b (D3).** Defined the two output predicate types in `specs/predicate.cue`
with hand-written Go types in `internal/deploy/predicate.go`: sealed SLSA
Provenance v1 statement (`#SLSAProvenanceStatement`) with strike's typed
`externalParameters` (including the declared OIDC identity, peers, observed
peers, resolver, engine connection), and the engine-context statement
(`#EngineContextStatement`) carrying only Layer-E claims (peer attribution,
engine metadata). Validated against the embedded CUE schema in
`predicate_test.go`. The internal `#Attestation` collect-model is unchanged.

### 2. SBOM core (D1)

Couple osv-scalibr as a modular library: import only the npm
`packagelockjson` extractor and the Debian `dpkg` extractor, never the
`extractor/filesystem/list` aggregator and never the image / disk scanner.
Drive the extractors through the thin in-process `fs.FS` walker (~100 lines)
over an already-extracted rootfs, to avoid the `extractor/filesystem ->
embeddedfs/common` disk-image cluster. Emit both formats via scalibr's
converters: CycloneDX canonical (`application/vnd.cyclonedx+json`) plus SPDX
2.3 first-class. Canonicalize the document (deterministic serial number and
namespace, SOURCE_DATE_EPOCH, stable component ordering). Remove the
`GenerateSBOM` buildinfo path in `internal/executor/sbom.go` in its entirety
(deletion, not a fix); surface an empty directory output at the producing
step as an INFO line. `cyclonedx-go` drops as a direct dependency (stays
transitive via scalibr at the identical v0.11.0). Includes an engine-backed
end-to-end test.

Depends on: instruction 1 (predicate types consume the SBOM as a subject).
Deletion gate: grep-verified reachability gate (report-only) on
`GenerateSBOM` and the buildinfo import before any edit.

### 3. Keyless signing (D2 + the D3 multi-attestation packaging)

Replace the operator-key DSSE path with the composed in-process chain:
ephemeral keypair, Fulcio short-lived certificate, DSSE, Rekor v2 upload and
bundle (sigstore-go/pkg/sign), interactive OIDC (sigstore/pkg/oauthflow),
referrer attach (go-containerregistry, already a dependency). No cosign CLI;
no exec. Sign the three layers as separate attestations so the V / E
boundary is physical: the sealed SLSA provenance, the engine-context
predicate, and the informational byproducts each become their own referrer.
ADR-013 retained: `sealed.rekor` is stripped before signature verification.

Depends on: instructions 1 and 2 (the predicates and the SBOM to be signed).
This is also the cross-roadmap unblock: see "Cross-roadmap dependencies".

### 4. Control-plane push (D4)

The control plane pushes the assembled image via go-containerregistry
`remote.Write`. Remove any engine push path; the engine may still pull by
digest for now but never pushes. Signing and referrer attach (instruction 3)
move to run after the control-plane push, on the registry digest, so the
signature covers the artifact as it exists on the wire.

Depends on: instruction 3 (sign-and-attach runs on the pushed digest).

### 5. strike verify (D3 verification exit + D5 cross-check)

Expose the `verify` subcommand in `cmd/strike` (today: `validate`, `dag`,
`run` only). Build on `internal/verify`: retain its DSSE / PAE / ECDSA P-256
core and add Fulcio certificate-chain verification, Rekor v2 inclusion (SET),
SLSA and SBOM predicate validation across the co-attached referrers, and the
D5 issuer / identity cross-check (cert issuer == declared issuer, cert SAN ==
declared identity). Per-layer exit is driven by trust mode: engine-trust
requires both V and E predicates; no-engine-trust requires only V;
informational never gates. The L3-versus-L2+ distinction is exactly this
switch -- whether E is trusted -- gating the two L3-only properties (build
isolation, complete externalParameters).

Depends on: instructions 1, 3, 4 (predicate shapes, keyless signatures, the
pushed registry digest the referrers hang off). Subsumes and redefines the
verify item the ADR-037 roadmap carried (see "Cross-roadmap dependencies").

## Parallel tracks (outside the strike code sequence)

- **osv-scalibr decoupling PR (upstream).** Decouples
  `embeddedfs/common` from the `extractor/filesystem` walker so the
  disk-image cluster no longer imports unconditionally. Once merged, the D1
  thin walker is dropped and strike returns to the upstream entry point.
  Independent of the instruction sequence; organic ecosystem visibility.
- **Local sigstore test harness.** docker-compose Fulcio + Rekor v2 +
  Keycloak (WebAuthn-passwordless, user verification required; Fulcio
  OIDCIssuers pointed at the Keycloak realm, type email; cosign >= v3.0.1 or
  >= v2.6.0 for Rekor v2). Exercises the live chain. This is a test
  environment, distinct from strike's in-process integration; it supports
  instructions 3 and 5 but is not part of the trusted binary.

## Cross-roadmap dependencies and ordering

- **ADR-040 instruction 3 (keyless) satisfies the ADR-038 D5.1 ordering
  dependency.** ADR-038's roadmap records that the signing key must be
  externalized (KMS / keyless) before the front's inbound listener is
  exposed in a remote deployment. Keyless is that externalization; the only
  durable secret becomes the OIDC identity. Instruction 3 is therefore a
  prerequisite for the remote-deployment exposure of the ADR-038 front, and
  the two roadmaps should be sequenced with instruction 3 ahead of any
  remote-front exposure.
- **ADR-040 instruction 5 (strike verify) subsumes the ADR-037 roadmap's
  pending verify item.** The ADR-037 roadmap lists a single open item: the
  `strike verify` CLI subcommand over the restructured predicate. ADR-040 D3
  redefines that subcommand's scope (referrers + Rekor inclusion + SLSA and
  SBOM predicate validation + the issuer / identity cross-check + per-layer
  trust-mode exit) and changes the signature model it must verify
  (operator-key DSSE -> keyless Fulcio chain). The verify work is now
  governed by this roadmap's instruction 5; the ADR-037 roadmap's item is
  retired in favor of it. `internal/verify` is the shared foundation, not a
  throwaway.

## Invariants the roadmap must respect

- Trust layers V (verify / observe; no false positive) and E
  (engine-dependent; silent false negative) per ADR-037, plus a non-gating
  informational bucket. ADR-040 D3 makes the V / E boundary physical (separate
  referrers), not a convention inside one signature.
- SLSA L3 under engine trust; L2+ otherwise, losing only complete
  externalParameters and build isolation. That single distinction surfaces as
  whether the E predicate is trusted (instruction 5).
- The control plane owns the wire: it pushes (D4) and already dials peers
  (container -> engine -> front -> capsule -> peer). The engine pulls but
  never pushes.
- Identity-first: signing identity (OIDC / Fulcio), peer identities (trust
  anchors, now including the IdP as a declared peer with a pinned anchor),
  artifact identity (digest). No long-lived key to hold.
- Everything external is digest-pinned; reproducibility is enforced
  (canonicalized SBOM, SOURCE_DATE_EPOCH, stable ordering); the signature
  covers the registry digest the control plane pushed.
- Code is liability: the cataloger and the signing stack are the leanest
  audited libraries that cover the task (measured by the two spikes); the
  thin walker is chosen over a heavy dependency. No exec: the keyless flow
  runs in-process as libraries, never by spawning a CLI.

## Open items

- **ADR granularity (carry-over from the handover).** ADR-040 was written and
  plumbed as one consolidating ADR; the index now lists it as a single
  Accepted record. The handover left open whether to decompose it into
  separate ADRs (SBOM generation / keyless signing / predicate packaging / CP
  push / OIDC schema), allocating ADR-041 ff. Permanent ADR numbering makes
  the split cheap but it must be decided before instruction 1 if a split is
  wanted. Default, absent a decision: keep ADR-040 consolidated as plumbed.
- **ADR-038 index discrepancy (flag, do not fix here).** The ADR-038 decision
  record states Status: Accepted, but `docs/ADR-INDEX.md` lists ADR-038 as
  Proposed. This is a pre-existing inconsistency, surfaced for the operator;
  it is not ADR-040 work. (The earlier ADR-039 index gap noted in the
  handover is now resolved -- 039 is present and Accepted.)

## References

- `docs/ADR-040-control-plane-sbom-and-keyless-attestation.md` -- governing ADR
- `HANDOVER-ADR-040-roadmap.md` -- design handover and decision basis
- `SPIKE-scalibr-import-surface.md`, `SPIKE-keyless-import-surface.md` -- the
  measurement spikes behind D1 and D2
- `sigstore-keyless-fido2-report.md` -- keyless / FIDO2 evaluation and the
  local-stack recommendation
- `docs/ADR-037-two-engine-trust-layers.md` -- the V / E trust-layer basis
- `docs/ADR-019-sbom-as-oci-referrer.md` -- SBOM mechanism partially superseded
  (referrer attachment and base-image resolution order retained)
- `docs/ADR-013-...` -- DSSE envelope and Rekor; `sealed.rekor` stripping retained
- `docs/ADR-038-protocol-mediated-ssh.md` -- the D5.1 ordering dependency
