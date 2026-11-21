# CUE Schema Workflow

CUE schemas define strike's complete data model. They serve four purposes:
input validation (lane YAML), output validation (attestations),
cross-implementation contracts exported as JSON Schema (the Rust verifier,
policy engines), and single-sourcing a canonical classification that other
schemas project from -- exported as JSON *data*, not schema, and machine-checked
by a conformance test. The worked example is the trust-layer map in
`contract/trustlayers/trust-layers.cue`: the sealed / engine-dependent /
informational classification, with its `layerOf` derivation table, that
`contract/attest/attestation.cue` (internal collect-model) and
`contract/attest/predicate.cue` (published statements) are both projections of.
`make generate` exports it to `contract/trust-layers.json` for external
verifiers and policy engines, and a conformance test asserts both schemas agree
with it -- the classification is stated once here and never restated in prose.
CUE is the single source of truth
(`DESIGN-PRINCIPLES.md#declarative-type-enforcement-cue-first`). The operative
imperatives -- when an agent must stop and ask, the single-source invariant
-- live in `AGENTS.md`; this document is the mechanical reference.

## Schema files

All contracts live under `contract/`, one CUE package per directory:

```
contract/
  primitive/    package primitive    -- scalar constraints (#Sha256, #Digest, ...)
  endpoint/     package endpoint     -- engine connection and the trust axis
  output/       package output       -- runtime output handles
  provenance/   package provenance   -- source-fetch provenance records
  record/       package record       -- artifact and SBOM provenance records
  lane/         package lane         -- lane input: peers, targets, transport, digests
  attest/       package attest       -- internal attestation, predicates, bundle
  trustlayers/  package trustlayers  -- trust-layer map, exported as data (trust-layers.json)
  crossval/     package crossval     -- cross-validation test vectors
  embed.go                           //go:embed of the schemas for runtime validation
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
3. **`make generate`** -- CUE must parse and validate, the JSON Schema export
   must succeed, and the Go types regenerate. Never hand-edit a generated
   file; if a generated type does not fit the Go code, fix the CUE schema, not
   the output.
4. **Implement the Go code against the generated or validated types.** A
   CUE-generated type is used directly. A CUE-validated Go type (e.g. in
   `deploy`) must serialize to JSON that passes its runtime validator.
5. **Update golden fixtures** with `make golden` and review the diffs to
   confirm the change produces the expected JSON.

## Field forms

Every field of a definition has one form per choice, and the validator
rejects every other form
(`docs/ADR-049-type-discipline-internal-seams.md`, rules (6) and (7) of
the amendment of 2026-11-20). A field is a named member of a struct,
declared or matched by a pattern; a list element is not a field. No field
holds `""`, `null`, `[]` or `{}`: a required field holds a non-empty
value, and an optional field is absent or holds one.

| Kind | Form, required or optional (`?`) |
|---|---|
| string | `string & !=""`, or a grammar that excludes `""` |
| list | `[T, ...T]` |
| map of pattern constraints | `{[K]: V} & struct.MinFields(1)` and `@go(Name,type=map[K]V)` |
| struct whose fields are all optional | `#T & struct.MinFields(1)` at the field that uses it, and `@go(Name,type=*T)` when optional |
| discriminator (`type`) | the required marker, as in `type!: "https"` |

A field with a default is a regular field with an explicit default arm
whose type follows the default, as in `forceRun: *false | bool`; it is
never optional. In an input it has three forms: omitted (the default
applies), the default written (pinned), and any other value.
`struct.MinFields` stands at the field, never in the definition, and a
struct whose fields carry defaults or constants holds a field the
instance must write. A definition carries no default of its own, and no
definition reaches itself, by a reference, a composition or an
embedding (amendment of 2026-11-21).

The two levels of the solution space; below level 1 the same holds
recursively.

| Value of a field `f` | required | optional |
|---|---|---|
| absent | invalid | valid |
| `""`, `null`, `[]` or `{}` | invalid | invalid |
| a non-empty value | valid | valid |

| Content of a non-empty `f` | list element | map entry | struct field |
|---|---|---|---|
| a non-empty value | valid | valid | valid |
| `""`, `[]` or `{}` | free; the element type decides | invalid | invalid |
| `null` | invalid by every type in the contract | invalid | invalid |
| absent, optional | -- | -- | valid |
| absent, required | -- | -- | invalid |

Two values of type `_` are exempt by a closed list in ADR-049; any other
is a defect.

## What `make generate` does

```sh
make generate     # go generate ./contract, which runs:
                  #   cue export ./lane ./attest --out jsonschema
                  #     -> contract/*.schema.json
                  #   cue export ./trustlayers --out json
                  #     -> contract/trust-layers.json
                  #   cue exp gengotypes over lane, primitive, endpoint,
                  #     output, provenance, record, attest
                  #   tools/genenums: rewrite contract/ imports to internal/,
                  #     move cue_types_gen.go to its internal home, recover
                  #     the enum constants gengotypes drops
```

The generated `internal/*/*.gen.go` files are gitignored, so acceptance greps
over them use plain `grep`, not `git grep`. CUE `@go()` attributes control the
generated Go type and field names; the `@go` annotation contract is
`docs/CODE-STYLE.md#cue-scalar-types`.

## Go types and CUE alignment

Two categories of Go types coexist:

**CUE-generated** (every package `make generate` runs gengotypes over):
produced into `internal/<pkg>/<pkg>.gen.go`, and for `attest` into
`internal/deploy/attest.gen.go`. Never hand-edit; the next `make generate`
overwrites it. Generated structs are exempt from the fieldalignment rule; see
`docs/FIELDALIGNMENT.md#cue-generated-types-are-exempt`.

**CUE-validated** (the `@go(-)` disjunction glue hand-written beside the
generated arms): validated at runtime against the embedded schema. JSON field
names must match the CUE field names exactly. A field added in Go but not CUE
fails validation; a field in CUE but not Go is missing from the output.

In both cases **CUE is authoritative**: when the Go code and the schema
disagree, the schema wins and the Go code is fixed.

## See also

- `AGENTS.md` -- the operative stop-and-ask rules for agents.
- `docs/CODE-STYLE.md#cue-scalar-types` -- the `@go` annotation contract.
- `docs/SPEC-PACKAGE-LAYERING.md`, ADR-047, ADR-048 -- package-tier design.
- `contract/README.md` -- the cross-implementation specification contract.
