# Spec Package Layering -- Design and Migration Reference

Structural reference for the `specs/` reorganization decided in
`docs/ADR-047-spec-package-layering.md`. It records the target layout, the
per-definition migration map, the scalar de-duplication the move enables,
and the harness-status markers for the meta specs. Planning state -- step
sequence, landed-vs-open -- is not here; it lives in the roadmap item store.

Anchor of record for the "today" side of the migration map: `bb914685`.

## Why

`specs/` today is four CUE packages, but the `lane` package is a merged
monolith: base scalars, the input wire (`#Lane`), the transport vocabulary,
the trust-root replica, the provenance records, and the internal API
(`#Artifact`) all share one namespace. Inside a package CUE resolves by name,
not by import, so nothing expresses a direction. Three concrete symptoms:
`lane.cue` mixes base scalars with the `#Lane` tree; `transport.cue` reaches
into `lane.cue` for base types; and `artifact.cue` (package `deploy`)
re-exports thirteen `lane` definitions as local aliases only so the output
wire can name them unqualified -- a CUE `deploy -> lane` import of the
input-wire package, and a second home for each of those names.

## Ratified layout

- **Four conceptual layers, named by filename prefix**, not by CUE package:
  `base-` (shared declarations and scalars), `api-` (internal runtime
  handoff), `wire-` (serialized input), `attest-` (serialized output). A
  fifth prefix, `meta-`, carries governance data that is not a contract.
- **Flat directory.** No subdirectories. The layer is the filename prefix, so
  the whole set is one reviewable listing.
- **The generated layers share one CUE package.** `base-`, `api-`, and
  `wire-` files all declare `package lane`. `cue exp gengotypes ./specs:lane`
  maps one CUE package to exactly one Go package; it cannot fold several CUE
  packages into one `internal/lane`, and an `import` statement makes a file's
  `@go()` target be ignored. One CUE package keeps one `internal/lane` with
  no cross-package import noise.
- **`attest-` is a separate CUE package**, `package attest` (renamed from
  `deploy`). It is hand-written and runtime-validated, not gengotypes-
  generated, so its CUE package name is free of its Go package name and it may
  `import` the lane package.
- **Import direction:** `base <- nothing`, `api <- base`, `wire <- {base,
  api}`, `attest -> {base, api}`. Output-wire never depends on input-wire.
  CUE enforces only `attest -> lane` natively (separate packages, acyclic by
  construction). The `base`/`api`/`wire` direction is within one package and
  is a prefix convention; a Go-over-CUE-API direction check is deferred.
- **Go-home alignment, no new `internal/` package.** `base`/`api`/`wire`
  target `internal/lane`; the transport subset of `base` stays `@go(-)`
  hand-written in `internal/transport`; `attest` stays hand-written and
  CUE-validated in `internal/deploy`.
- **The bridge is deleted, not relocated.** The thirteen `lane.#X` aliases in
  `artifact.cue` are removed; output-attestation files import the lane package
  once and name shared declarations qualified.

## Target file layout

```
specs/
  base-scalars.cue     package lane    Digest Sha256Hex Base64 Int64String
                                       GitCommit Identifier Path AbsPath
                                       RelPath ImageRef Duration ArtifactType
  base-transport.cue   package lane    Host TLSTrust FingerprintTrust
                                       CABundleTrust DNSResolver HTTPSEndpoint
                                       EngineConnection (+ Unix/ServerTLS/TLS/MTLS)
                                       @go(-) -> internal/transport
  base-peer.cue        package lane    Peer HTTPSPeer SSHPeer KnownHostEntry
  base-target.cue      package lane    DeployTarget
  base-provenance.cue  package lane    ProvenanceRecord + Git/Tarball/OCI/URL

  api-artifact.cue     package lane    Artifact

  wire-lane.cue        package lane    Lane tree (Step, Pack, Deploy, OIDC,
                                       Keyless, refs, recording, ...)
  wire-trustroot.cue   package lane    TrustedRootReplica CertAuthorityReplica

  attest-attestation.cue   package attest  Attestation collect-model
  attest-predicate.cue     package attest  SLSA / EngineContext / Informational
  attest-bundle.cue        package attest  Bundle (+ verification material)
  attest-artifact-record.cue package attest ArtifactRecord SBOMRecord

  meta-trust-layers.cue  package trustlayers   classification map + status marker
  meta-crossval.cue      package crossval      vector schema + status marker

  embed.go               (re-wired //go:embed vars for the new file set)
```

Only `attest`, `trustlayers`, and `crossval` are distinct CUE packages; the
`base-`/`api-`/`wire-` prefixes are all `package lane`. The prefix is the
layer; the CUE package boundary is only between `lane` and the three others.

## Migration map (source file at bb914685 -> target)

| Today | Definitions | Target file | CUE package |
|-------|-------------|-------------|-------------|
| `lane.cue` (base part) | Digest, Identifier, Path/AbsPath/RelPath, ImageRef, Duration, ArtifactType | `base-scalars.cue` | lane |
| `lane.cue` (peer part) | Peer, HTTPSPeer, SSHPeer, KnownHostEntry | `base-peer.cue` | lane |
| `lane.cue` (target) | DeployTarget | `base-target.cue` | lane |
| `lane.cue` (rest) | Lane, Step, Pack*, Deploy*, OIDC, Keyless, *Ref, recording, SBOMConfig, ... | `wire-lane.cue` | lane |
| `transport.cue` | Host, TLSTrust*, DNSResolver, HTTPSEndpoint, EngineConnection* | `base-transport.cue` | lane |
| `source-provenance.cue` | ProvenanceRecord + 4 records | `base-provenance.cue` | lane |
| `sigstore-trustroot.cue` | TrustedRootReplica, CertAuthorityReplica | `wire-trustroot.cue` | lane |
| `artifact-api.cue` | Artifact | `api-artifact.cue` | lane |
| `attestation.cue` | Attestation, Sealed, EngineDependent, Informational, Observed*, ResolverRecord, EngineMetadata, Timestamp | `attest-attestation.cue` | attest |
| `predicate.cue` | DigestSet, ResourceDescriptor, Subject, SLSA*, StrikeExternalParameters, ProvenanceOIDC, EngineContext*, Informational* | `attest-predicate.cue` | attest |
| `sigstore-bundle.cue` | Bundle, VerificationMaterial, DSSEEnvelope, TransparencyLogEntry | `attest-bundle.cue` | attest |
| `artifact.cue` (real content) | ArtifactRecord, SBOMRecord | `attest-artifact-record.cue` | attest |
| `artifact.cue` (bridge block) | 13 `lane.#X` aliases | DELETED | -- |
| `trust-layers.cue` | trust-layer map | `meta-trust-layers.cue` | trustlayers |
| `crossval.cue` | vector schema | `meta-crossval.cue` | crossval |

`package deploy` becomes `package attest`: wire- and golden-neutral (the
package name is never serialized) and the Go home `internal/deploy` does not
move, because no gengotypes runs on this package.

The Go home for the lane-package files is `internal/lane`, except the
`base-transport.cue` subset, which carries `@go(-)` and is hand-written in
`internal/transport`.

## De-duplication this enables

The same value constraints are re-inlined across files today. Consolidating
them under `base-scalars` removes the copies (one home per meaning):

- `^sha256:[a-f0-9]{64}$` -- in `lane.#Digest`, re-inlined in
  `OCIProvenanceRecord.digest`; collapses to `base.#Digest`.
- bare 64-hex -- in `predicate.#DigestSet.sha256`; becomes `base.#Sha256Hex`.
- base64 `^[A-Za-z0-9+/]+={0,2}$` -- in `KnownHostEntry.key`,
  `sigstore-bundle.#Base64`, and the trust-root `rawBytes` (currently a bare
  string); becomes `base.#Base64`.
- 40/64-hex commit -- in `GitProvenanceRecord.commit` and
  `#DigestSet.gitCommit`; becomes `base.#GitCommit`.
- `^[0-9]+$` int64 string -- `sigstore-bundle.#Int64String`; moves to base.

These are wire-neutral: the regex is identical, only its home changes. Each
is its own small step in the roadmap store, not bundled blindly.

## The meta specs and their (partial) harness

Neither meta spec is a wire or API contract; both are governance data whose
enforcement mechanism is only partly built. The reorg adds an in-file,
greppable status marker so the gap is visible, e.g. a `_harnessStatus` field:

- `meta-trust-layers.cue` -- single source of the V / E / informational
  classification; `attest-attestation` and `attest-predicate` are projections
  of it. The conformance harness exists but is partial: only the
  `engineDependent` and `informational` sections and their published
  predicates are machine-checked. The sealed (V) section and the
  SLSA-provenance `externalParameters` projection are pinned in the map but
  not yet checked. Marker text states exactly that gap.
- `meta-crossval.cue` -- language-independent test-vector schema for a second
  implementation. The vectors are schema-validated and run through the Go
  implementation, but there is no second implementation yet, so the
  cross-implementation comparison the vectors exist for is unbuilt. Marker
  text states exactly that gap.

A small test asserting each marker matches reality keeps the marker from
going stale; that test is roadmap scope, not part of the reorg landing.

## Why the layers are not separate CUE packages

A package-per-layer design (`base`, `api`, `wire` each their own CUE package)
would give a CUE-native import DAG across all four layers for free. It is not
taken, because `cue exp gengotypes` maps one CUE package to exactly one Go
package: three `@go(lane)` packages do not fold into one `internal/lane`, and
an `import` statement makes the `@go()` target be ignored. Separate packages
for the generated layers would therefore split `internal/lane` into several
Go packages or force new `internal/` packages, against the flat, no-new-
package shape this design keeps. The single-package layout trades the
machine-checked intra-`lane` DAG for one Go package; the package-per-layer
route is recorded in ADR-047 as the deferred alternative and tracked in the
roadmap store.

## Consequences to schedule (not part of the reorg landing)

- `AGENTS.md` "Schema files" and "Package structure" blocks list the current
  `specs/` layout; they update after the reorg lands (doc-only, bundled by
  review concern).
- `specs/README.md` and `specs/embed.go` enumerate the current file set; both
  re-wire to the new files.
- The directional-import check (a small Go tool over the CUE API) is deferred;
  CUE's `attest -> lane` acyclicity is the only structural guard initially.
- Makefile prerequisite lists and the `make generate` / `make specs` selectors
  target the current file set; they re-point at the new files. The generated
  selector stays `./specs:lane`; the attestation package selector follows the
  `attest` rename.
