# CUE Spec Review Roadmap (post trust-boundary formalization)

## Status: OPEN -- two arcs remain (D-D field-add, D-F: B-4, B-5, B-8..B-9)

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
| B-4 | `id` / `name` normalization (stop overloading `name`) | Landed. B-4a (`52026b17`), B-4b (`8916ca08`), B-4c (`bf6756c6`). See "B-4 -- ratified plan" below. |
| B-5 | Unify producer refs on `#OutputRef`; reconcile `from` / `source` | Ratified -- Option A (structured `#OutputRef`) for the three dotted producer refs; single arc. `imageFrom` is a step ref, not a producer-output ref -- split to its own arc (see Deferred). See "B-5 -- ratified plan" below. |
| B-6 | `#TLSTrust` discriminator `mode` -> `type` + one enum casing | Landed `22426cc2`. `transport.cue` `#TLSTrust` keys on `type:` with values `certFingerprint` / `caBundle`; the hand-mirrored Go (`@go(-)`) moved in lockstep, and the golden bundles were regenerated (re-keying `golden/lane.yaml` re-hashes its sealed `laneDigest`). |
| B-7 | De-overload "attestation" (rename the state-capture config) | Landed `d8cabc2`. `recording` / `#StateRecording` (plus `#CaptureSet` / `#Capture`) replaces the `attestation` / `#AttestationSpec` config; the cryptographic-attestation family is untouched; golden bundles regenerated. ADR-016 vocabulary. |
| B-8 | Apply `#AbsPath` / `#RelPath` consistently or comment opaque path fields | Partial. Types exist and are applied in places; audit coverage at write time. |
| B-9 | P3 polish: `#SignerIdentity` dedup, `clientId` -> `audience`, `trustRootRef` `@go` symmetry, default-disjunction order | Pending. |

Execute in the order documented in ROADMAP-STATUS.md:
B-4 / B-5 next (naming, broader blast radius; B-6/B-7 landed),
then B-8 / B-9 (polish). Each is its own PR per the ratification.

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

### B-4 -- ratified plan (`id` / `name` normalization via `#Identifier`)

The overload: `name` does double duty as both human-display and the
cross-reference identifier across several types, while the identifier role is
itself named three ways -- `#Lane.laneId`, `#DeployTarget.id`, and `#Step.name`
(no separate id). The same identifier pattern `=~"^[a-z0-9][a-z0-9-]{0,62}$"` is
copy-pasted inline four times across two packages (`lane.cue` l.22 / l.406;
`attestation.cue` l.70; `predicate.cue` l.89) -- a single-sourcing violation.
That pattern is a *loose* RFC 1123 DNS label: correct charset and the 63-char
DNS-label length, but it does not force an alphanumeric final character
(`build-` wrongly passes).

**Ratified convention.** A cross-referenced entity identifier is named `id` and
constrained by a single canonical type; `name` is human-display only. Grounded
in the ecosystem: GitHub Actions uses `id` (the reference handle) plus `name`
(UI display); "label" is rejected because in Kubernetes / OCI a label is a
key-value selection map, not a display string.

**Canonical type (ratified).** Define once in `package lane`, reference
everywhere the entity-identifier role appears -- including the `package deploy`
mirrors, which already import `package lane`:

```
// #Identifier is a stable, cross-referenceable entity id. The grammar is the
// RFC 1123 DNS label (lowercase alphanumeric and '-', start and end
// alphanumeric, at most 63 chars) so an id is usable verbatim as a Kubernetes
// resource name, an OCI tag component, and a DNS label.
#Identifier: =~"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$"
```

Strict RFC 1123 (leading digit allowed); underscores are out (they break
k8s / OCI / DNS), which forces a small value migration. No separate ADR.

**Reference set.** Adopt `#Identifier` for: `#Lane` id (was `laneId`, plus its
mirrors in `attestation.cue` and `predicate.cue`), `#DeployTarget.id`, and --
after the rename -- `#Step.id`, `#OutputSpec.id`, `#Capture.id`. Explicitly
excluded (different vocabularies): `clientId` (OAuth aud), `logId` / `keyId`
(base64), `#SLSABuilder.id` (a URI per the SLSA spec), `uid` / `gid` (POSIX
ints). `#SecretRef.name` is out of scope entirely -- that type is semantically
underdetermined and tracked separately.

**Three stages, each its own PR (isolated by risk):**

- **B-4a -- single-source the identifier (pure refactor, lowest risk).** Landed `52026b17`. Add
  `#Identifier`; replace the four inline patterns with it. The end-anchor
  tightening breaks nothing (no current `laneId` / `#DeployTarget.id` value ends
  in a hyphen). No rename, no value migration. Settles the cross-package wiring
  once.
- **B-4b -- rename `name` -> `id` (mechanical, large).** Landed `8916ca08`. Identifier-role
  `name` -> `id` and `laneId` -> `id`; Go fields and YAML keys. Each field keeps
  its current type: `#Lane.id` / `#DeployTarget.id` stay `#Identifier` (from
  B-4a); the freshly renamed `#Step.id` / `#OutputSpec.id` / `#Capture.id` stay
  plain `string` for now. No value migration. Golden regen (the `name:` -> `id:`
  key recase re-keys `golden/lane.yaml`).
- **B-4c -- apply `#Identifier` and migrate values (semantic).** Landed `bf6756c6`. Type the renamed
  `#Step.id` / `#OutputSpec.id` / `#Capture.id` as `#Identifier`, and migrate the
  underscore identifiers to hyphens in the four fixtures that carry them
  (`fan_out_lane.yaml`, `hugo.yaml`, `hugo_like_lane.yaml`,
  `image_from_lane.yaml`), fixing the dotted `"step.output"` references in
  lockstep. Golden regen if affected (the golden lane is already slug-clean, so
  its values need no migration).

B-5 (`#OutputRef`; reconcile `from` / `source`) stays a strictly separate arc.

**Docked finding -- output-side symmetry would be a restructuring, not a rename.**
B-4b (Option 1) leaves the attestation/predicate output fields `laneId` /
`laneDigest` untouched: in the flat signed predicate they are self-documenting,
and renaming `laneId` -> `id` on its own would strand it beside `laneDigest` as
the lopsided `{id, laneDigest}`. Genuine input/output symmetry would not be a flat
rename but a nesting -- `#StrikeExternalParameters: {lane: {id: #Identifier,
digest: #Digest}, ...}`, with the matching change to `#Sealed`. That blast radius
is strictly larger than B-4b's: it changes the signed wire format, the
cross-validation vectors, the trust-layers `internal` paths (`sealed.laneId` ->
`sealed.lane.id`), the published SLSA-provenance mapping, and the hand-mirrored Go
output structs. Deferred; out of the B-4 arc.

### B-5 -- ratified plan (`#OutputRef`; unify producer refs)

Ratified direction: Option A -- a structured canonical type
`#OutputRef: {step: #Identifier, output: #Identifier}`, replacing the three
dotted encodings of the producer-output-reference concept. At anchor
`673f5cfd` those are `#InputRef.from` (l.196), `#PackFile.from` (l.320), and
`#ArtifactRef.from` (l.403), each a dotted `"step.output"` string. They all
parse through one splitter, `parseRef` in `internal/lane/dag.go` (call sites
at the input / pack-file / artifact references).

`#ImageFrom` is NOT a producer-output ref and is out of B-5. It expresses
multi-stage "base image = the image a previous step produced" -- a reference
to a step, not to a named output. It is rebuilt in its own arc (see
Deferred) as `imageFromStep: #Identifier`, XOR with `image`, resolved by
pulling the step's canonical engine image
`localhost/strike/<lane-id>/<step-id>`.

"Reconcile `from` / `source`" resolves by demonstration: no `source` field
is a producer ref. `#DeployRegistry.source` / `target` are registry image
locations, `#DeploySpec.source.gitImage` is an `#ImageRef`, and
`#CaptureMount.source` is a mount path. They stay a distinct concept, out of
B-5 scope; a later pure-naming pass, if wanted, is its own arc.

Single arc (the earlier `#ImageFrom` fold that motivated a split proved to
be a different concept; see above). Define `#OutputRef`; re-type
`#InputRef.from` / `#PackFile.from` / `#ArtifactRef.from` as `#OutputRef`;
migrate every dotted `from: step.output` fixture value to the structured
form; delete `parseRef` and rewire its three call sites to read
`.From.Step` / `.From.Output`; drop `parseref_internal_test.go` (the parser
it covers is gone).

Field naming stays `from:` (its value becomes `#OutputRef`); a rename was
not adopted. Each ref component is validated as `#Identifier`, and the
dotted-string parser is deleted (code-is-liability).

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
- **`imageFromStep` rebuild** -- `#Step.imageFrom` (`#ImageFrom {step,
  output}`) mis-models multi-stage base images. Correct model: a step's base
  image is `image` (digest-pinned external) XOR a previous step's produced
  image, referenced by step id alone. Rebuild as `imageFromStep:
  #Identifier` (drop `output`), keep the existing `image` / `imageFrom` /
  `pack` / `deploy` XOR (already enforced in `parse.go`), and have the
  resolver pull the step's canonical engine image
  `localhost/strike/<lane-id>/<step-id>`. Its own arc; not started.

## Archival

Remove this file with `git rm` once D-B+D-G, the D-D field-add, and the full
D-F queue have landed and every deferred item above has either landed or moved
to its own roadmap. Until then this file is the single source for the
cue-spec-review planning state.
