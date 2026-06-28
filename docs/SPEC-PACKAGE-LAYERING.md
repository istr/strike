# Spec Package Layering -- Structural Reference

Structural reference for the CUE contract under `contract/`: the package layout,
each package's role, and the dependency direction the layout enforces. The
rationale -- why the contract is partitioned this way -- lives in the ADRs cited
inline: `docs/ADR-047-spec-package-layering.md` (the package split),
`docs/ADR-044-tier-assignment-criterion.md` (the inward-only tier model), and
`docs/ADR-048-contract-type-semantics.md` (the concept tier and the
define/specify type semantics).

## Layout

The contract is one CUE package per directory under `contract/`. The runtime
embeds the whole tree (`contract/embed.go`) and `internal/schema` presents it as
a CUE module, loading each package natively via `cue/load`.

```
contract/
  primitive/    package primitive    irreducible scalar vocabulary
  endpoint/     package endpoint     host/address, TLS trust, HTTPS + engine identity
  output/       package output       runtime output handles
  provenance/   package provenance   source-fetch provenance records
  target/       package target       deploy destination
  record/       package record       artifact and SBOM provenance records
  lane/         package lane         operator-authored input wire format
  attest/       package attest       deploy attestation contract + published predicates
  trustlayers/  package trustlayers  trust-layer classification map (governance)
  crossval/     package crossval     cross-validation vector schema
  embed.go                           //go:embed of the package tree
```

## Package roles and dependency direction

The contract value types depend inward only: a package may name types from a
lower layer, never a higher one. Cross-package `import` statements make the
direction explicit in the CUE, and go-arch-lint enforces the Go projection of
the same DAG (`.go-arch-lint.yml`).

- **primitive** -- the leaf vocabulary: content-addressed digests, identifiers,
  hashes, and the other irreducible scalar constraints. Depends on nothing.
- **concept tier** -- `endpoint`, `output`, `provenance`, `target`, `record`:
  composed value types that each depend only on `primitive`. The names are
  destuttered against their package (`output.#Handle`, `target.#Deploy`,
  `provenance.#Git`, `record.#Artifact`), so a qualified call site reads without
  repetition.
- **lane** -- the operator-authored input wire format: the `#Lane` tree, network
  peers (over `endpoint.#TLS`/`#SSH`), and the trust-root replica. It composes
  primitive and concept types.
- **attest** -- the deploy attestation contract: the internal collect-model
  (`#Attestation`), the published in-toto / SLSA predicates, and the sigstore
  `#Bundle`. It is the one package that names the others, importing lane,
  concept, and primitive.

## Generated vs hand-written Go

`make generate` runs `cue exp gengotypes` over `primitive`, `endpoint`,
`output`, `provenance`, `target`, `record`, and `lane`, landing generated Go in
`internal/<pkg>/<pkg>.gen.go` (gitignored, never hand-edited). The `@go`
annotations in those packages name the Go field and type for each definition.

`attest`, `trustlayers`, and `crossval` are not generated. `attest` carries no
`@go` redirects: its Go types are hand-written in `internal/deploy` and the CUE
is runtime-validation only. This is deliberate -- the attestation types include
discriminated unions (the observed-peer and engine-connection identities) whose
dispatching `UnmarshalJSON` gengotypes cannot emit -- and it lets the attest CUE
package `import` the lane and concept packages freely.

## One CUE package per directory

`cue exp gengotypes` maps one CUE package to exactly one Go package, and an
`import` statement makes a file's `@go()` target be ignored. So each generated
contract package is its own directory and its own Go package; there is no
merged, multi-package directory. The separation also gives CUE a native, acyclic
import DAG across the contract, which is the cross-package half of the
inward-only dependency rule.

## Exported contract

For consumers without a CUE runtime, `make specs` exports JSON Schema --
`contract/lane.schema.json` (lane input) and `contract/attestation.schema.json`
(deploy attestation), plus `contract/trust-layers.json`. These are the
cross-implementation contract a secondary verifier builds against.
