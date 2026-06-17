# ADR-044: Deterministic tier assignment for internal packages

## Status

Accepted.

## Context

strike's internal packages are layered into five tiers -- foundation, transport,
services, orchestration, entry -- enforced by `.go-arch-lint.yml` under one
invariant: dependencies may not point upward across tiers. The enforcement is
structural and reliable. The *assignment* of a package to a tier, however, has
not been governed by any written rule. The `.go-arch-lint.yml` header annotates
each tier with an instability range (`I = Ce/(Ca+Ce)`) and a one-line role word,
but that annotation is descriptive of the current members, not a criterion for
placing a new one.

The cost of that gap surfaced concretely: the DSSE pre-authentication encoder and
the in-toto payload type were homed in `internal/deploy` (an orchestration role
package) although they are generic wire-format primitives the consumer
(`internal/verify`) must also use. That produced a backwards `verify -> deploy`
edge -- legal to the linter (intra-tier orchestration edges were permitted) and
caught only by the compiler when a second edge closed the cycle. A misplaced
primitive should be a lint failure against a stated criterion, not a latent cycle
found at build time.

A deterministic, documented criterion makes placement verifiable instead of
discretionary, and gives future "where does this package go" decisions a single
authoritative answer.

## Decision

A package's tier is the **lowest tier permitted by the no-upward rule given its
actual internal (efferent) dependencies.** Concretely, classify by what the
package imports from other internal packages:

- **foundation** -- no internal dependencies. A foundation package imports no
  other internal package, not even another foundation package.
- **transport** -- depends only on foundation.
- **services** -- depends only on foundation and transport, plus intra-services
  edges.
- **orchestration** -- depends on services (and, transitionally, other
  orchestration packages) and below.
- **entry** -- the composition root; may depend on anything below.

This is computable from the import graph alone and therefore deterministic.

The instability metric `I = Ce/(Ca+Ce)` in the `.go-arch-lint.yml` header is a
**descriptive cross-check**, not the assignment rule: a correctly placed package's
measured `I` falls within its tier's annotated band. Afferent count (who imports
the package) does not determine its tier -- a package does not choose its layer by
counting its consumers.

Where more than one tier is legal for a package -- which can only happen for the
home of a contract shared by two role packages -- the **domain-owner** tiebreak
(CODE-STYLE) applies: the package that owns the concept's domain is its home, and
a contract shared by two roles is owned by neither role package but extracted into
a role-neutral noun package at the tier its dependencies dictate.

**Corollary -- tier is reality-tracking, not aspirational.** A package's tier is a
function of its *current* internal dependencies and changes when those change. A
package extracted with no internal dependencies is foundation; if shared behavior
that depends on a services-tier package is later added to it, it is reclassified
to services at that point -- a one-line `.go-arch-lint.yml` change justified by the
new edge. A package is never placed in a higher tier in anticipation of
dependencies it does not yet have; doing so would make the criterion
non-deterministic.

**The rule governs the logical dependency, not the import graph alone.** A tier
edge forbidden by the no-upward rule, the foundation no-internal-dependency rule,
or the orchestration no-intra-tier-edge rule may not be satisfied by injecting the
dependency from the composition root -- a function-typed field, a consumer-defined
interface, reflection, or any indirection whose effect is to relocate the
forbidden import to a higher tier while the depended-on functionality stays where
it is. When package A's correctness depends on package B's functionality, that is a
dependency whether or not A names B in an import statement; it is resolved by
placing B, or the shared functionality, at its criterion-correct tier so the edge
is a legal static import -- not by hiding it behind a seam. Injection remains
legitimate only for genuine polymorphism or test substitution that does not cross
a tier boundary to evade this rule.

## Consequences

- Tier membership becomes a checkable property: a reviewer (or a future CI guard)
  can derive each package's tier from its imports and compare it to its declared
  component, rather than relying on judgment.
- The deploy/verify wire-format primitives are extracted into a role-neutral
  `internal/bundle` (a separate change). With only `bytes`/`strconv` dependencies,
  `bundle` has no internal dependencies and is therefore **foundation** under this
  criterion. It is reclassified to services if and when shared behavior depending
  on services-tier packages is added to it.
- A package that changes its dependency floor changes tier. This is intended:
  the layer always reflects the real dependency structure.
- Forbidding any internal dependency in foundation -- including edges between
  foundation packages -- closes two loopholes at the source: a cross-reference
  between foundation packages can never form a cycle, and foundation cannot
  accumulate into an internally coupled cluster. The foundation tier holds no
  intra-tier edges today, so the rule is enforceable immediately. (Enforcing it
  in `.go-arch-lint.yml` is implementation, separate from this decision.)
- `internal/verify` depends only on services-tier (`lane`, `registry`) and
  foundation-tier (`clock`, `bundle`) packages, so by this criterion it is a
  services package, not orchestration. It was initially mis-placed in
  orchestration; the injection seam that let `internal/deploy` reach it without a
  static import is removed in favor of the legal downward import once `verify`
  sits at its criterion-correct tier.

## Principles

- **Enforcement is structural, not discretionary** -- placement becomes a rule
  derived from the import graph, not a per-case judgment, and is mechanically
  checkable against the enforced no-upward invariant.
- **Meaning is single-sourced** -- one criterion governs all tier assignment, and
  a contract shared by two roles is given one authoritative home rather than being
  owned by one side or duplicated.
- **Code is liability** -- a misplaced primitive that invites a cycle is treated
  as the defect it is; the criterion removes the class of error at its root.
