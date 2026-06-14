# CUE Spec Review Roadmap (post trust-boundary formalization)

## Status: OPEN -- two arcs remain (D-D field-add, D-F: B-4, B-5, B-7..B-9)

This roadmap is the single source for the work-arcs derived from
`RETROSPECTIVE-cue-spec-review.md`. The post-formalization handover note
summarizes this state but does not own it. State below is grounded at commit
`8721d0ff78b771b012f311c059c5ccd9b36fcb84` ("refactor: derive the trust layer
from provenance, machine-checked"); re-ground at write time before authoring any
instruction, because the formalization landed on a branch and the mainline tip
may differ.

## Two label spaces -- do not conflate them

The originating review produced two overlapping numbering schemes. Keep them
distinct:

- **Cluster findings** (the retrospective's own IDs): `A-1..A-5` (docs),
  `B-1..B-9` (substantive, gate-verifiable), `C-1..C-5` (schema / codegen),
  `D-1..D-3` (process / foundational docs).
- **Arc / decision labels** `D-A..D-G`: the ratified work-arcs derived from
  those findings. These are what instruction files refer to.

## Arcs (ratified disposition)

| Arc | What it is | Ratified disposition |
|-----|------------|----------------------|
| D-A | Keyed image-signing / Rekor-v1 surface (`cosign_key`, `executor/rekor.go`, `executor/sign.go`, `initRekor`, `#RekorEntry` / `#InclusionProof`); resolves C-1. | Remove -- keyless everything. Signed-intermediates is a future keyless arc, not preserved as legacy keyed code. |
| D-B | Canonical / trusted time of the deploy attestation. | Trusted time = RFC3161 TSA (per ADR-040). Fix the `integratedTime` / ADR-037 claims; re-cite ADR-040. Bundle with D-G. Operator-owned. |
| D-C | Canonical layer of `engineMetadata` (C-4). | Canonical = informational; move it out of `#EngineContextPredicate`. |
| D-D | Sealed fields of `#EngineConnection` (engine-cert subject / issuer triage). | "If it can be solid V, include it." Became the trust-boundary formalization; the field-add itself is still pending. |
| D-E | Model Bundle / DSSE in CUE (C-2, the one true CUE-first gap). | Close the CUE-first gap; it is a contract violation. |
| D-F | Naming / validation conventions (B-1..B-9). | Treat each as a separate instruction -- one B-finding per PR. |
| D-G | Adopt "Meaning is single-sourced" (D-2), qualify the aim sentence (D-1), canonical-time doc fixes, stale ARCHITECTURE.md passage. | Do exactly that; bundle with D-B into one instruction. Operator-owned. |

## What has landed (verified at-tree, 8721d0ff)

- **Cluster A (docs sweep).** `specs/README.md` lists all schemas and separates
  internal (`attestation.cue`) from published (`predicate.cue`);
  `#ProvenanceRecord` attribution fixed.
- **D-A -- keyed signing + Rekor v1 removal.** D-A-1 (atomic removal + ADR-043)
  landed `80098903`; D-A-2 (keyed prose reconciliation + three workflow
  learnings) landed `12292c87`. Resolves C-1. The stale ARCHITECTURE.md keyed
  passage ("same cosign key") is gone.
- **D-C -- `engineMetadata` -> informational.** Done in schema, Go structs, and
  projection: `predicate.cue` files it under `#InformationalPredicate`;
  `project.go` routes it to the informational statement. Resolves C-4.
- **D-D formalization -- trust-boundary decision procedure.** Landed `8721d0ff`.
  Layer is derived from provenance via the `layerOf` rule table in
  `specs/trust-layers.cue`; machine-checked by `TestLayerDecisionProcedure`;
  `hardenedByDeclaration` records the resolver/observedPeers-hardened vs
  engine-not-yet-hardened asymmetry as data. This is the formalization, not the
  field-add (see "Open arcs -> D-D field-add").
- **D-E -- Bundle / DSSE in CUE.** Landed with the verify arc
  (`specs/sigstore-bundle.cue` plus the keyless consumer). Resolves C-2.
- **C-5 -- conformance test + `make specs` export** of `trust-layers.json`.
  Landed and extended in the formalization arc.
- **B-1 -- `#Lane.registry` regex.** Landed. The pattern is anchored both ends
  with ports permitted:
  `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?(/[a-z0-9._-]+)*$`.
- **C-3 -- published-envelope mediaType.** Published envelopes use
  `application/vnd.in-toto+json`; the strike mediaType is an internal label
  only. Resolved, no change needed.
- **D-B + D-G -- trusted time and single-sourcing.** D-B corrected every spot
  that claimed Rekor `integratedTime` is canonical to "the RFC3161 TSA token is
  the trusted time (ADR-040)": `SECURITY.md` wallclock section,
  `ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md`, `specs/attestation.cue`,
  `specs/predicate.cue` (two comments), and `specs/trust-layers.cue` (comment +
  the timestamp-row rationale -- one more spot, `attestation.cue`, than this
  roadmap had enumerated). D-G added the "Meaning is single-sourced" principle to
  `DESIGN-PRINCIPLES.md` after "Declarative type enforcement (CUE first)" and
  qualified the aim sentence (end-to-end under a trusted engine, best-effort and
  scope-marked otherwise), matching `README.md` and the soundness note's
  commitment 1.

## Open arcs

Execute in the order documented in ROADMAP-STATUS.md.

### D-D field-add -- engine-cert subject / issuer into `#EngineConnection`

A schema field-add (CUE-first ratification gate applies) plus wiring the Go
projection to stop dropping the fields. The Go `ConnectionInfo` / `TLSIdentity`
observes `serverCertSubject`, `serverCertIssuer`, `clientCertSubject` (read from
`resp.TLS.PeerCertificates[0]` in `internal/container/engine.go` and
`podman.go`) but drops them at `engineRecords` (`deploy.go` ~l.977); the closed
CUE `#EngineConnection` (`specs/attestation.cue` ~l.201) does not declare them.
The decision procedure gives the clean home: `provenance: cpObserved -> V`,
`hardenedByDeclaration: false` (observed, not yet declaration-hardened). Honest
caveat: the engine dial uses standard `net/http` TLS (`container/tls.go`
`Build()`), not strike's hardened transport -- so these are
observed-but-not-pinned; the field-add records them at V truthfully, and the
later engine-transport arc is what flips `hardenedByDeclaration` to true.

**Docked finding -- `caTrustMode` vocabulary (from the B-6 follow-on).** The
per-peer trust discriminator `#TLSTrust.type` (`certFingerprint` | `caBundle`,
landed in B-6) and the engine CA-trust selector `#EngineConnection.caTrustMode`
(`pinned` | `system`) are the same kind of choice -- how a server certificate is
trusted -- named with different suffixes (`type` vs `Mode`). The
"`mode`-for-scalars, `type`-for-unions" defense does not hold: the sibling scalar
enum `connectionType` (`"unix" | "tls" | "mtls"`) on the very same
`#EngineConnection` already uses `type`. So the split is not a signal; it is the
de-overloading / least-surprise class this review exists to catch (cf. B-4 "stop
overloading name", B-5 "reconcile from/source"). Recommended direction (ratify at
write time, NOT yet ratified): retire the `Mode` suffix for kind-selectors,
`caTrustMode` -> `caTrustType`, matching `#TLSTrust.type` and the sibling
`connectionType`; `connectionType` stays. The values `pinned | system` most
likely stay as-is -- a different mechanism vocabulary than
`certFingerprint | caBundle`, plausibly on purpose -- decide explicitly at write
time. This is docked here, not split out, because `#EngineConnection` lives under
`#Sealed.engine` (`specs/attestation.cue` ~l.96), so `caTrustMode` is in the
signed payload: renaming it changes the sealed wire format and inherits the
golden-bundle + crossval regen dependency (see the golden-regen note under D-F
below), exactly the sealed shape the D-D field-add already opens and regenerates.
Grounding pins (anchor `22426cc2`): `specs/attestation.cue` `#EngineConnection:`
~l.201, `connectionType:` ~l.203, `caTrustMode?:` ~l.207; Go mirror
`internal/deploy/deploy.go` `CATrustMode` ~l.202 (`json:"caTrustMode,omitempty"`),
projection ~l.982. Open decisions for the future instruction: exact target name;
whether the values move; whether this folds into the D-D field-add or stands
alone as a new D-F item.

### D-F -- B-2..B-9 schema findings (one instruction each)

At-tree state verified at `8721d0ff`; B-1 is done, the rest pending.

| ID | Finding | At-tree state |
|----|---------|---------------|
| B-2 | `gitCommit` canonical width | Landed. `predicate.cue` `gitCommit` widened to 40-or-64, matching `source-provenance.cue` `commit`. |
| B-3 | `#Subject` should reuse `#ResourceDescriptor` (remove bespoke type) | Landed. `#Subject` is now `#ResourceDescriptor` refined with required name and digest; no duplicated structure, Go mirror unchanged. |
| B-4 | `id` / `name` normalization (stop overloading `name`) | Pending; re-survey at write time. |
| B-5 | Unify producer refs on `#OutputRef`; reconcile `from` / `source` | Pending. Both still used in `lane.cue` (l.190 / 314 / 380 / 397 / 440). |
| B-6 | `#TLSTrust` discriminator `mode` -> `type` + one enum casing | Landed `22426cc2`. `transport.cue` `#TLSTrust` keys on `type:` with values `certFingerprint` / `caBundle`; the hand-mirrored Go (`@go(-)`) moved in lockstep, and the golden bundles were regenerated (re-keying `golden/lane.yaml` re-hashes its sealed `laneDigest`). |
| B-7 | De-overload "attestation" (rename the state-capture config) | Pending. `lane.cue` still says "state attestation" (l.6, l.350). Carries the golden-regen gate: the golden lane declares a deploy step with a state-capture (`attestation:`) block, so this rename re-keys `golden/lane.yaml` -- plan the regen step from the outset (see the golden-regen note below), do not plan it as hermetic. |
| B-8 | Apply `#AbsPath` / `#RelPath` consistently or comment opaque path fields | Partial. Types exist and are applied in places; audit coverage at write time. |
| B-9 | P3 polish: `#SignerIdentity` dedup, `clientId` -> `audience`, `trustRootRef` `@go` symmetry, default-disjunction order | Pending. |

Execute in the order documented in ROADMAP-STATUS.md:
B-7 next (single-concern schema fix; B-6 landed at `22426cc2`),
then B-4 / B-5 (naming, broader blast radius), then B-8 / B-9 (polish). Each is
its own PR per the ratification.

**Golden-bundle regen is a hard dependency for golden-affecting B-x items.** Any
schema or naming change that re-keys `internal/verify/testdata/golden/lane.yaml`
-- or changes the bytes of any file whose digest is sealed into a golden DSSE
bundle -- is NOT hermetic: the sealed predicate seals a digest over the file and
the DSSE signature covers the payload, so the bundle must be regenerated against
the local sigstore harness, never hand-edited. Before calling such a change
hermetic, decode the base64 DSSE payloads and look for sealed `*Digest` fields
over any file the change edits; a plaintext grep over base64 payloads is
insufficient (it is exactly what produced the B-6 `make test` defect --
observation defeats declaration). The regen recipe lives in
ROADMAP-sigstore-test-harness.md under "Downstream consumers". B-7 inherits this
gate (see its row above).

## Deferred (out of this arc)

Recorded here so they are not lost; none is started under this roadmap.

- **2c base-SBOM signature verification** -- unblocked by the keyless consumer,
  not started. Also noted in ROADMAP-ADR-040 and ROADMAP-ADR-041.
- **Engine hardening / transport-unification** -- the larger arc that flips the
  engine `hardenedByDeclaration` to true; entangled with DNS centralization and
  the remote-engine horizon. D-D's field-add is the small precursor.
- **DNS centralization** -- DoT client + container-facing resolver to the front.
- **Full TLS single-port demux** -- remote-engine / routed rootless-netns
  horizon (needs L3 source-IP preservation; pasta splice-only cannot provide it).
- **Upstream osv-scalibr PR** -- decouple disk-image extractors from the
  filesystem extractor import path.
- **ARCHITECTURE.md threat-row judgment** ("Signing key exfiltrated", ~l.172) --
  surfaced during the D-D arc, not yet actioned.
- **`SignedArtifact` rename** -- post-keyless the name is a digest+SBOM
  misnomer; cosmetic cleanup.

## Archival

Remove this file with `git rm` once D-B+D-G, the D-D field-add, and the full
D-F queue have landed and every deferred item above has either landed or moved
to its own roadmap. Until then this file is the single source for the
cue-spec-review planning state.
