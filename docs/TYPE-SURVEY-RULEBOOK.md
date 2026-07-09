# Type Survey Rulebook

Version 1. Ratified 2026-07-09 against tree `5945d91`.

This document is the input handed verbatim to every agent that surveys the tree
for type-safety findings, and to every agent that verifies such a survey. It
states how a finding is classified and what makes a verdict admissible. It does
not state architecture: the architectural rules the verdicts below generalize to
are permanent and live in [ADR-049](ADR-049-type-discipline-internal-seams.md).

This document is revisable. A survey wave that discovers a rule the catalog
cannot express amends it here, with a new clause number; existing clause numbers
are never reused for a different rule.

## How to use this document

A survey produces findings. A verification stage adjudicates them. Both cite
clause numbers from this file. A verdict without a citation is a defect of the
audit, not a disagreement about the code -- the two lanes of the 2026-07-07
dual audit reached opposite verdicts on the same field precisely because each
improvised a rule instead of citing one.

Clause prefixes: `RB-nn` for classification rules, `BC-nn` for the boundary
catalog. The boundary catalog enumerates what is *not* a finding.

## Classification rules

### RB-01 -- The verdict set is exhaustive and every verdict is cited

Every finding on an untyped or under-typed value terminates in exactly one of
three verdicts, and each carries a citation:

- **D1, unapplied type.** A type that models this value exists. The verdict
  names it and the definition that makes it apply.
- **D2, missing type.** No type models this value. The verdict names the value
  grammar and its recurrence count. This is a finding of the vocabulary-gap
  class, filed against `contract/`. It is not a rejection.
- **Boundary.** The site is legitimate. The verdict cites a `BC-nn` clause.

"No type applies" is not a verdict. It is the premise of D2.

### RB-02 -- Findings are split per field before adjudication

A finding whose subject is more than one field is decomposed into one finding
per field before any verdict is reached. Adjudicating a bundle rejects the
strong member along with the weak one, and the rejection carries the reason of
only one of them.

### RB-03 -- A projection outside the owning package is D1

A method or function that converts a concept value into a wire grammar, sited
outside the package that defines the concept, is D1 against the defining
package. The named-type conversions it performs on the concept's fields are the
symptom; the missing method is the finding. See ADR-049 (2).

Named assignments (`h := string(a.Host)`) pass `linttypeconv` by design. Passing
that linter is not a boundary citation.

### RB-04 -- A grammar-closed method returning a plain string is D1

A method whose result is still a member of its receiver's grammar, but whose
declared result type is `string`, is D1 -- inside the owning package as much as
outside it. The owning-package exemption covers conversion sites; it does not
cover signature design. See ADR-049 (3).

`String()` is exempt (`fmt.Stringer`). No other method name is.

Corollary: when such a method exists, its callers' string handling is not an
independent finding. It is the consequence, and it closes when the cause closes.
Filing the consequence while exempting the cause is the error this clause was
written to prevent.

### RB-05 -- Repeated schema inspection of an unmodelled raw input is D1

When a raw input carries a discrimination that no type models, and the target
forms of that discrimination *are* modelled, the finding is D1 against the
missing parser -- not D2 against the missing compound type. The first inspection
is the parser; every further inspection is the finding. See ADR-049 (1).

D2 applies only when the target forms themselves are unmodelled.

### RB-06 -- An internal signature is not a boundary by resemblance

A strike-internal function whose parameter shape imitates a foreign idiom is not
thereby a boundary. The boundary is the foreign call. Where a sibling function in
the same package accepts the typed value, the resemblance is D1. See ADR-049 (4).

### RB-07 -- Deferrals carry owners

Every deferral this rulebook's verdicts produce -- a D2 vocabulary gap, a
blocked remediation, an allowlist entry -- carries the roadmap item id that owns
it. This is the authoring clause of `AI-WORKFLOW.md`, restated here because a
survey agent has no other reason to read that file.

## Boundary catalog

### BC-01 -- Third-party handles

A value of a third-party type that produces its own string is not a strike
detype. `v1.Hash.String()` never held a strike type.

The clause covers exactly one direction, foreign to string. Two counter-directions
remain findings:

- a value that is already a strike type and is converted back to `string`;
- a strike value passed as `string` into a foreign call whose library accepts its
  own type for that argument.

### BC-02 -- Log and error formatting

Applying a formatting verb (`%s`, `%q`, `%v`) to a typed value inside a log call
or an `fmt.Errorf` is not a detype. The value is projected into a message, not
into program state.

The exclusion is scoped to the formatting expression. A value derived for
logging that crosses a function boundary -- a sanitized name threaded as a
parameter beside the typed value it was derived from -- is program state, and is
D1.

### BC-03 -- Wire-discriminator literals

A string literal equal to a union's wire discriminator is legitimate at the
serialization or deserialization seam owned by the union's own package. The
literals there are the JSON contract.

Outside that seam -- a producer that assigns the discriminator, a consumer that
switches on it -- the literal is a symptom and the field's `string` type is the
finding: D1. Whether named constants are reachable from the consumer's package is
a separate, owned question and does not change the verdict.

## Adjudicated disputes

The disputed set of the 2026-07-07 dual type-safety audit, ruled per this
rulebook. The register rows are those of
`retrospectives/2026-07-07-dual-type-safety-audit.md`, section 7.

| Row | Subject | Verdict | Clause | Owner |
|---|---|---|---|---|
| R-20 | OIDC `issuer` (3 sites) | D1 | RB-01, RB-02 | item-0076 |
| R-20 | OIDC `identity` (3 sites) | D2, grammar "Fulcio SAN" | RB-01, RB-02 | item-0076 |
| R-34 | engine address, scheme-parsed threefold | D1 | RB-05 | item-0086 |
| R-35 | `known_hosts` host projection outside `endpoint` | D1 | RB-03 | item-0087 |
| R-36 | `DialTCP` packed-string parameter | D1 | RB-06 | item-0088 |
| R-37 | path grammar-method shapes | D1 | RB-04 | item-0079 |

Two E-internal contradictions close with R-20: finding 145 (kept, citing an
existing URL type) and rejection 155 (rejected as "no scalar applies") are the
same question. Under RB-02 the bundle splits; under RB-01 the weak half becomes
D2 rather than a rejection. Neither lane was wrong about its half.

The codifications of section 8.6, which no register row carries:

| Subject | Verdict | Clause | Owner |
|---|---|---|---|
| `v1.Hash.String()` and peers | boundary | BC-01 | -- |
| `safeName` threaded beside `stepID` | D1 | BC-02 | item-0089 |
| `unix`/`tls`/`mtls` in `UnmarshalEngine` | boundary | BC-03 | -- |
| the same literals in `container` and `deploy` | D1 | BC-03 | item-0090, item-0092 |

## Amendment log

- Version 1, 2026-07-09: initial ratification. RB-01 through RB-07, BC-01
  through BC-03, and the disputed set of the 2026-07-07 dual audit.
