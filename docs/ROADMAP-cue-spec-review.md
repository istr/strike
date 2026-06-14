# CUE Spec Review Roadmap (post trust-boundary formalization)

## Status: OPEN -- two arcs remain (D-D field-add, D-F: B-2..B-9)

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

## Open arcs (recommended order)

### 1. D-D field-add -- engine-cert subject / issuer into `#EngineConnection`

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

### 2. D-F -- B-2..B-9 schema findings (one instruction each)

At-tree state verified at `8721d0ff`; B-1 is done, the rest pending.

| ID | Finding | At-tree state |
|----|---------|---------------|
| B-2 | `gitCommit` canonical width | Pending. `predicate.cue` `gitCommit` is 40-hex only; `source-provenance.cue` `commit` allows 40 or 64. Divergent. |
| B-3 | `#Subject` should reuse `#ResourceDescriptor` (remove bespoke type) | Pending. Both still defined separately in `predicate.cue` (l.41 vs l.50). |
| B-4 | `id` / `name` normalization (stop overloading `name`) | Pending; re-survey at write time. |
| B-5 | Unify producer refs on `#OutputRef`; reconcile `from` / `source` | Pending. Both still used in `lane.cue` (l.190 / 314 / 380 / 397 / 440). |
| B-6 | `#TLSTrust` discriminator `mode` -> `type` + one enum casing | Pending. `transport.cue` still uses `mode: "cert_fingerprint"` / `"ca_bundle"`; `#Peer` / `#TrustRoot` already use `type:` -- this is the inconsistency. |
| B-7 | De-overload "attestation" (rename the state-capture config) | Pending. `lane.cue` still says "state attestation" (l.6, l.350). |
| B-8 | Apply `#AbsPath` / `#RelPath` consistently or comment opaque path fields | Partial. Types exist and are applied in places; audit coverage at write time. |
| B-9 | P3 polish: `#SignerIdentity` dedup, `clientId` -> `audience`, `trustRootRef` `@go` symmetry, default-disjunction order | Pending. |

Recommended D-F order: B-2, B-3, B-6, B-7 first (single-concern schema fixes),
then B-4 / B-5 (naming, broader blast radius), then B-8 / B-9 (polish). Each is
its own PR per the ratification.

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
