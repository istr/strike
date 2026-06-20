# ADR-047: Spec layering -- file-prefix layers in one generated CUE package

## Status

Accepted. Relates to [ADR-004](ADR-004-cue-as-single-source-of-truth.md)
(CUE as the single source of truth), which placed every cross-boundary and
serialized contract in CUE without separating the kinds that have since
diverged; [ADR-044](ADR-044-tier-assignment-criterion.md) (deterministic
tier assignment), the Go-side analogue of single-sourcing a structure's
home; and [ADR-046](ADR-046-one-canonical-digest-pinned-image.md), whose
internal artifact-handover type this layering gives a named home.

## Context

ADR-004 put all of strike's data contracts in CUE but did not distinguish
two kinds that have since pulled apart: the serialized **wire** formats an
operator authors (lane input) or an external verifier consumes (deploy
attestation), and the internal **runtime API** -- the typed handoff between
strike's own pipeline phases, carrying content-addressed values that cannot
exist at authoring time (`#Artifact` in `specs/artifact-api.cue`).

Today `specs/` is four CUE packages, and the `lane` package is a merged
monolith: base scalars, the `#Lane` input wire, the transport vocabulary,
the trust-root replica, the provenance records, and the internal `#Artifact`
API all share one namespace. Inside a CUE package, references resolve by
name rather than by import, so no direction between these concerns is
expressible, let alone enforceable. The symptoms are concrete:

- `lane.cue` mixes base scalars (`#Digest`, `#AbsPath`, `#Identifier`) with
  the full `#Lane` input tree.
- `transport.cue` reaches into `lane.cue` for base types because they live
  in the same namespace, with nothing marking transport as a lower layer.
- `artifact.cue` (package `deploy`) re-exports thirteen `lane.#X`
  definitions as local aliases, purely so the output-attestation wire can
  name them unqualified. That alias block is a CUE-level `deploy -> lane`
  import of the input-wire package -- exactly the coupling a layering should
  forbid -- and it is a second home for each of those thirteen names.

The Go side already avoids this: `internal/deploy` imports `internal/lane`
and `internal/transport` under qualified names and has no bridge. The CUE
structure and the Go structure disagree, and the CUE side is the looser one.

## Decision

**(1) Four conceptual layers, named by filename prefix.** Every spec file
carries one of five prefixes: `base-` (shared declarations and scalars),
`api-` (internal runtime handoff), `wire-` (serialized input), `attest-`
(serialized output), and `meta-` (governance data that is not a contract:
the trust-layer classification map and the cross-validation vectors). The
layer a definition belongs to is legible from the filename alone.

**(2) One flat `specs/` directory.** No subdirectories. The whole
specification set is one `ls` listing, reviewable by a person at a glance.

**(3) The generated layers share one CUE package.** `base-`, `api-`, and
`wire-` files all declare `package lane`. This is forced by the code
generator, not a preference: `cue exp gengotypes ./specs:lane` maps one CUE
package to exactly one Go package. It cannot fold several CUE packages into a
single `internal/lane`, and adding an `import` statement to a CUE file makes
that file's `@go()` package target be ignored. Keeping the generated layers
in one CUE package is what keeps the generated Go in one `internal/lane`
without cross-package import noise. The `attest-` files form a **separate**
CUE package, `package attest` (renamed from `deploy`): it is hand-written and
validated against CUE at runtime, not gengotypes-generated, so its CUE
package name is decoupled from its Go package name and it may legally
`import` the lane package.

**(4) Import direction, and what enforces it.** The intended direction is
`base <- nothing`, `api <- base`, `wire <- {base, api}`, and
`attest -> {base, api}`; output-wire never depends on input-wire. The only
edge CUE enforces natively is `attest -> lane`: they are separate packages,
the lane package never imports attest, so the boundary is acyclic by
construction. The `base`/`api`/`wire` direction lives **within** the single
lane package and is therefore a filename-prefix convention, not a
package-import constraint; a dedicated direction check (a small Go tool over
the CUE API) is deferred, and until it exists that direction is enforced by
review, not by a machine. This reduced enforcement is the deliberate cost of
emitting one Go package.

**(5) The re-export bridge is deleted, not relocated.** The thirteen
`lane.#X` aliases in `artifact.cue` are removed. Output-attestation files
import the lane package once and name each shared declaration qualified
(`lane.#X`) at its use site. No alias home survives, so each shared
declaration has exactly one definition.

**(6) CUE boundaries align to the existing Go homes; no new `internal/`
package.** `base`/`api`/`wire` are Go-homed in `internal/lane` (generated);
the transport subset of `base` stays `@go(-)` hand-written in
`internal/transport`; `attest` stays hand-written and runtime-validated in
`internal/deploy`. The transport vocabulary -- `#EngineConnection`,
`#DNSResolver`, `#HTTPSEndpoint`, and the TLS trust types -- carries the
`base-` prefix, Go-homed unchanged in `internal/transport`: transport
identity is base vocabulary, and fidelity to the existing Go home outweighs
the "shared by more than one layer" guideline for the prefix choice.

## Consequences

- The `lane.cue` monolith splits along the prefixes. Value constraints
  currently re-inlined across files (the sha256, base64, git-commit, and
  int64-string patterns) consolidate under `base-`, one home each. These are
  wire-neutral moves: identical bytes, different home.
- `package deploy` becomes `package attest`. Wire- and golden-neutral, because
  a CUE package name is never serialized and the Go validation home
  (`internal/deploy`) does not move.
- The output-attestation package stops importing input-wire definitions
  through a bridge; it imports the lane package once and names shared
  declarations qualified.
- The `base`/`api`/`wire` direction is not machine-checked at landing; CUE
  gives acyclicity only at the `attest -> lane` boundary. A Go-over-CUE-API
  check that enforces the intra-package direction is tracked as deferred work
  in the roadmap store.
- A fully package-per-layer alternative -- `base`, `api`, and `wire` each
  their own CUE package, yielding a CUE-native import DAG across all four
  layers -- was considered and deferred. Under the one-CUE-package-to-one-Go-
  package mapping it would split `internal/lane` into several Go packages or
  require new `internal/` packages, reverting the flat, no-new-package shape
  this decision keeps. It is the only route to a machine-checked DAG across
  every layer, so it is recorded here as the deferred alternative and tracked
  in the roadmap store.
- Documentation and wiring that enumerate the current layout -- `AGENTS.md`
  ("Schema files" and "Package structure"), `specs/README.md`, and
  `specs/embed.go` -- update as the reorg lands. Those are doc-and-wiring
  changes bundled by review concern, separate from this decision record. The
  structural reference for the move is `docs/SPEC-PACKAGE-LAYERING.md`.
- Moving definitions between CUE files and packages is a confirmation-gated
  change under `AGENTS.md`. The operator has ratified this layering; each
  landing step still carries its own confirmation gate and byte-exact
  contract.

## Principles

- **Declarative type enforcement (CUE first)** -- the layering is expressed
  in the CUE schema set itself (one generated package, one separate `attest`
  package, prefix-named layers), keeping CUE the single source the Go types
  are generated from rather than a structure imposed on the Go side after
  the fact.
- **Meaning is single-sourced** -- deleting the re-export bridge leaves every
  shared declaration with exactly one definition, reached by qualified
  reference everywhere else, instead of an alias home that can drift from the
  original.
- **Code is liability** -- the bridge is removed rather than relocated, no new
  Go package is introduced, and duplicated value constraints collapse to one
  home; the change removes surface instead of adding it.
