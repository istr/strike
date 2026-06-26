# ADR-048: Contract type semantics -- naming by role, representation-neutral concepts, and the primitive/concept layering

## Status

Accepted. Supersedes [ADR-047](ADR-047-spec-package-layering.md), which layered
the specification by filename prefix inside one generated CUE package; that
arrangement was a transitional step and its concern -- separating the kinds of
contract type that had pulled apart -- is subsumed here on a semantic footing
rather than a mechanical one.

Amends [ADR-044](ADR-044-tier-assignment-criterion.md) by adding a concept tier
between foundation and transport. Sharpens
[ADR-046](ADR-046-one-canonical-digest-pinned-image.md): the wire-versus-internal
digest distinction it relied on is resolved into a single representation-neutral
concept. Concretizes [ADR-004](ADR-004-cue-as-single-source-of-truth.md) (CUE as
the single source of truth) by naming the two registers a contract carries, and
extends [ADR-042](ADR-042-field-naming-camelcase.md) from field naming to the
naming of types and the packages that hold them.

## Context

The contract is a set of CUE files. It is normative: it states what must be true,
language-neutrally. Every implementation -- the Go this project generates, and any
independent second implementation a verifier might write -- is a derivation of the
contract, not a peer of it. This is the whole point of single-sourcing the
contract in CUE (ADR-004): correctness means conformance to the shared contract,
never code-to-code agreement.

Two structural facts follow from that stance, and most naming and layering
decisions follow from those two facts. They had not been written down.

First, the internal form of a value cannot name its external (wire) form. A value
whose struct imported, or was named after, its serialization could not be checked
the same way in two languages: one implementation's "wire digest" type is not a
contract artifact, it is an implementation artifact. The transformation between
internal value and wire bytes must live at the boundary that knows the
representation, pointing outward, never inward into the value.

Second, the contract carries two registers that had been conflated. Some
definitions *define* a type -- a record assembled from other contract types, or an
irreducible whose identity is a pattern. Others *specify* a constraint -- a wire
grammar, a precondition, a conformance vector -- that generates a check, not a
type. Treating a wire grammar as if it were a type produces a standalone
"wire-string" type that internal code then carries around, which is exactly the
representation leak the first fact forbids.

The package and type naming the project had reached for named accidents rather
than essences. The interim home for the shared irreducibles was called `spec`
(after its source) and its file `scalars` (after the values' form). The
content-addressed digest existed twice: a wire-string type `Digest` (named after
the wire form) and a structured value `DigestRef` (named after its mechanism, a
"reference"), bridged by hand. Both names describe something accidental about the
thing -- where it comes from, what shape it has, what mechanism it is -- and none
survives a move, a reshape, or a reimplementation.

A durable model is needed: how to name a type-bearing area, how the CUE contract
maps onto generated code, where wire/value transforms live, and what tier a
contract-derived value type occupies. The model below is derived from the two
facts above and from the project's existing tier discipline; it is meant to
outlive any particular package list.

## Decision

### (1) Name by role, not by mechanism, shape, or position

A type-bearing area is named for its **intrinsic role** -- what the thing is --
not for what its definitions *do* (a mechanism word like "constraint"), the
*form* its values take (a shape word like "scalar"), or *where it sits* relative
to neighbors (a position word like "leaf"). Role is the only register that
survives refactors that move, reshape, or reimplement the thing; the other three
name an accident of its current circumstances.

Concept identity is carried by the **type name**; architectural position is
carried by the **package**. The same concept across representations keeps one type
name, disambiguated only by its package qualifier, and a type name never restates
its own package. There is no `provenance.ProvenanceRecord` and no `primitive.PrimitiveSha256`;
there is `provenance.Record` and `primitive.Sha256`. The call site reads without
stutter, and the concept's identity is independent of where it is homed.

### (2) Two registers in the contract: define and specify

A CUE definition is one of two kinds, and the kind determines what it generates:

- **Define** (`#Foo: { ... }` or `#Bar: <pattern>` whose identity is the type) --
  generates a type. These map one-to-one onto a concept package or onto the
  primitive package.
- **Specify** (a wire grammar applied to a boundary field, a pre/postcondition, a
  conformance vector) -- generates a check, executed at a boundary, not a type.

A value's wire form is a specify-register constraint, not a define-register type.
The canonical text form of a content-addressed digest is a grammar
(`sha256:<64 hex>`) checked where the digest crosses the serialization boundary;
it is not a type that internal code holds. Independent verification is conformance
to shared, contract-defined vectors: both implementations generate their types
from the same `define` set and execute the same `wire <-> value` vectors as tests.
That is only possible because the generated types are representation-neutral.

### (3) The irreducible primitives: package `primitive`

The contract's **irreducible** types -- those whose identity is a pattern or a
closed literal set, not assembled from other contract types -- are cross-cutting
and share one home. By (1) that home is named for its role: these are the
contract's own primitive, given types, so the package is **`primitive`**
(CUE package `primitive`, generated Go `internal/primitive`). The usual objection
that "primitive" means language built-ins dissolves at the namespace:
`primitive.Sha256` is unambiguously a contract primitive. This name cleaves the
type space along the intrinsic axis -- composed versus irreducible -- rather than
along "shared" (too broad) or position.

A type-bearing area holds named, code-generating **types** only. It must not also
hold **composition fragments**: private predicate pieces that exist solely to be
interpolated into real types and that generate nothing. Such fragments are mortar,
not members; they stay private and below the named types.

```cue
// contract: primitive
#Sha256:    =~"^[a-f0-9]{64}$"   // a named primitive -- a member; generates a type
_sha256Body: "[a-f0-9]{64}"      // mortar -- a private fragment; generates nothing
```

The test for the role word staying honest: every public member of `primitive` is
something a consumer can name and parse into; nothing in it is a bare validation
snippet.

### (4) Composed values are concepts -- representation-neutral, concept-first

A value assembled from other contract types is a **concept**. Each concept owns
one type name and lives in its own package named for that concept. The concept's
representation-neutral value is the generated type; its wire grammar is a specify
constraint per (2); and the transforms between the two -- parse (text to value)
and render (value to text) -- live in the **same package, outward of the value**,
hand-written over the generated type, importing no serialization into the value
itself. This mirrors the standard-library shape (`net.ParseIP`/`IP.String`,
`time.Parse`/`Time.Format`): one concept package, two directions, no stutter, and
both the internal and the external form dissolve into the concept rather than into
a global `model` or `wire` bucket. There is therefore no monolithic vocabulary
package. A separate wire/codec layer is admitted only as a deliberate exception,
where the wire and internal forms diverge structurally enough to require
independent generation -- justified by divergence, never by habit.

The content-addressed digest is the worked example. Its representation-neutral
value is one concept type:

```go
// internal/digest -- concept-first, stutter-free, representation-neutral
type Digest struct {            // the value; no serialization import, no wire name
    Algorithm Algorithm
    Hex       primitive.Sha256  // the 64-hex grammar is single-sourced in primitive
}
func Parse(s string) (Digest, error) { /* "sha256:<hex>" -> Digest */ }
func (d Digest) String() string      { /* Digest -> canonical "sha256:<hex>" */ }
```

There is no standalone wire-string `Digest` type and no `DigestRef`. The wire
string is a boundary constraint built from `primitive.Sha256`; the value is
`digest.Digest`; the two directions are `Parse` and `String`.

### (5) The concept tier

A **concept** tier is added between foundation and transport. A concept package
depends only on the `primitive` foundation package, and every tier above it --
transport, services, orchestration, entry -- may take a downward edge to it. This
gives the serialized output contract (the deploy attestation) and the
cross-validation vectors a home that depends only on primitives and concepts,
never on the input-wire or services packages -- removing the last reason those
serialized contracts reached up into the lane package for shared vocabulary.

This extends the tier list of ADR-044 (contract, foundation, transport, services,
orchestration, entry) to place concept above foundation and below transport, under
the same no-upward invariant. ADR-044 assigns a package to the lowest tier its
dependency floor permits; concept and transport can share the floor "depends only
on foundation," so their boundary is settled by **kind**, exactly as the
contract/foundation boundary is: a concept package owns a contract-derived value
type and its representation-neutral behavior (parse/render); a transport package
is network carriage (TLS, SSH, HTTPS dialing). The distinction is mechanically
legible -- a package homing a generated contract value type plus its `Parse`/
`String` is concept; a package whose surface is connection establishment is
transport.

```
contract       embedded CUE; depends on nothing
  foundation     primitive (irreducible types) + the existing logic-free utilities
    concept        digest, provenance, deploy target -- value + Parse/String
      transport      carriage (TLS/SSH/HTTPS)
        services       behavior / operations
          orchestration  pipeline
            entry          composition root
```

Dependencies point only inward. The granularity -- how many concept packages --
is a scaling choice under the same invariant: a concept is split out when its
value and transforms form a self-contained unit, and concepts are not collected
into a meta-named grab-bag, because `digest.Digest` reads at the call site where
`model.Digest` or `vocab.Digest` would not.

## Consequences

- The interim `primitive`-role package (homed during the scalar extraction under
  the name `spec`) is named `primitive` and holds **only** irreducible types. The
  composed types that arrangement would otherwise have absorbed -- the deploy
  target and the provenance records -- are extracted into concept packages
  instead, never into the primitive package.
- The digest is unified: the structured value becomes `digest.Digest`, the
  wire-string type and the `DigestRef` name are removed, and the parse/render
  functions move into the digest concept package. The wire grammar survives only
  as a boundary constraint built from `primitive.Sha256`. This resolves the
  wire-versus-internal split ADR-046 described into one concept; ADR-046's image
  and output model is otherwise unchanged.
- The deploy attestation and the cross-validation vectors depend only on
  `primitive` and concept packages. The vocabulary coupling from the serialized
  contracts up into the input-wire/services package -- the coupling ADR-047's
  re-export bridge was deleted to avoid -- is structurally gone, not merely
  unbridged.
- `.go-arch-lint.yml` gains a concept component between foundation and transport,
  with `mayDependOn: [primitive]` and every higher tier granted a downward edge to
  it; ADR-044's tier table gains the concept row. (The configuration is the
  implementation of this decision, separate from it.)
- The package count rises by the concept packages. This is the intended trade:
  call-site clarity (`digest.Digest`, `provenance.Record`) and a type space cleaved
  on the composed-versus-irreducible axis, against a single role-neutral bucket
  that reads worse and mixes the two kinds. The mortar rule keeps each area's
  public surface to parse-able members only.
- Tier assignment stays reality-tracking per ADR-044: a concept package that
  later grows a dependency on a higher tier is reclassified at that point; it is
  not pre-placed.

## Principles

- **CUE first** -- the contract is the single, language-neutral source; the
  define/specify split names how it projects into generated types and boundary
  checks, and the representation-neutral core is the precondition for checking two
  implementations against one contract.
- **Meaning is single-sourced** -- each concept has exactly one type name and one
  home; the digest's two former types collapse to one, and a wire grammar is
  single-sourced as a constraint rather than duplicated as a type.
- **Enforcement is structural** -- the inward-only tier invariant, extended with
  the concept tier, makes the dependency direction of contract-derived value types
  a checked property rather than a convention.
- **Code is liability** -- removing the duplicate digest type and the re-export
  coupling, and keeping mortar out of the named type areas, deletes surface rather
  than adding it; the added concept packages buy clarity that a grab-bag would
  cost back at every call site.
