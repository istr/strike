# CUE Schema Workflow

CUE schemas define strike's complete data model. They serve four purposes:
input validation (lane YAML), output validation (attestations),
cross-implementation contracts exported as JSON Schema (the Rust verifier,
policy engines), and single-sourcing a canonical classification that other
schemas project from -- exported as JSON *data*, not schema, and machine-checked
by a conformance test. The worked example is the trust-layer map in
`contract/trustlayers/trust-layers.cue`: the V / E / informational
classification, with its `layerOf` derivation table, that
`contract/attest/attestation.cue` (internal collect-model) and
`contract/attest/predicate.cue` (published statements) are both projections of.
`make specs` exports it to `contract/trust-layers.json` for external verifiers
and policy engines, and a conformance test asserts both schemas agree with it
-- the classification is stated once here and never restated in prose. CUE is
the single source of truth
(`DESIGN-PRINCIPLES.md#declarative-type-enforcement-cue-first`). The operative
imperatives -- when an agent must stop and ask, the single-source invariant
-- live in `AGENTS.md`; this document is the mechanical reference.

## Schema files

All contracts live under `contract/`, one CUE package per directory:

```
contract/
  primitive/scalars.cue   package primitive   -- scalar constraints (#Sha256, #Digest, ...)
  lane/                   package lane         -- lane input: peers, targets, transport, digests
  attest/                 package attest       -- internal attestation, predicates, bundle
  endpoint/               package endpoint     -- engine connection and the trust axis
  trustlayers/            package trustlayers  -- trust-layer map, exported as data (trust-layers.json)
  crossval/               package crossval     -- cross-validation test vectors
  embed.go                //go:embed of the schemas for runtime validation
```

`cue exp gengotypes` maps one CUE package to exactly one Go package, so each
package needs its own directory -- a flat layout cannot host multiple CUE
packages. Files in one directory that share a `package` declaration are
merged by CUE automatically; no import is needed.

## Schema-first development

Changes that introduce or alter a data structure follow this order:

1. **Define the CUE type first** in the appropriate `contract/<pkg>/*.cue`
   file, with field constraints (regex, bounds, enums) and a doc comment on
   every field.
2. **Stop and ask the operator** before writing any Go. A schema change is an
   architectural decision: it affects every implementation (Go, Rust
   verifier, external tools) and every existing attestation in every
   registry. This is the stop trigger stated in
   `AGENTS.md#stop-and-ask-the-operator`.
3. **`make specs`** -- CUE must parse and validate, and the JSON Schema export
   must succeed.
4. **`make generate`** -- regenerate the Go types. Never hand-edit a generated
   file; if a generated type does not fit the Go code, fix the CUE schema, not
   the output.
5. **Implement the Go code against the generated or validated types.** A
   CUE-generated type is used directly. A CUE-validated Go type (e.g. in
   `deploy`) must serialize to JSON that passes its runtime validator.
6. **Update golden fixtures** with `make golden` and review the diffs to
   confirm the change produces the expected JSON.

## What `make generate` does

```sh
make specs        # cue export ./contract/<pkg> --out jsonschema -> contract/*.schema.json
                  # plus contract/trust-layers.json
make generate     # runs specs, then:
                  #   cue exp gengotypes ./contract/{lane,primitive,endpoint}
                  #   sed: rewrite contract/ import paths to internal/
                  #   mv   cue_types_gen.go -> internal/{lane,primitive,endpoint}/*.gen.go
```

The generated `internal/*/*.gen.go` files are gitignored, so acceptance greps
over them use plain `grep`, not `git grep`. CUE `@go()` attributes control the
generated Go type and field names; the `@go` annotation contract is
`docs/CODE-STYLE.md#cue-scalar-types`.

## Go types and CUE alignment

Two categories of Go types coexist:

**CUE-generated** (packages `lane`, `primitive`, `endpoint`): produced by
`cue exp gengotypes` into `internal/<pkg>/<pkg>.gen.go`. Never hand-edit; the
next `make generate` overwrites it. A fieldalignment finding on a generated
struct is fixed in the CUE field order, then regenerated -- see
`docs/FIELDALIGNMENT.md`.

**CUE-validated** (e.g. package `deploy`): hand-written Go, validated at
runtime against the embedded schema. JSON field names must match the CUE
field names exactly. A field added in Go but not CUE fails validation; a field
in CUE but not Go is missing from the output.

In both cases **CUE is authoritative**: when the Go code and the schema
disagree, the schema wins and the Go code is fixed.

## See also

- `AGENTS.md` -- the operative stop-and-ask rules for agents.
- `docs/CODE-STYLE.md#cue-scalar-types` -- the `@go` annotation contract.
- `docs/SPEC-PACKAGE-LAYERING.md`, ADR-047, ADR-048 -- package-tier design.
- `contract/README.md` -- the cross-implementation specification contract.
