# 2026-07-12 -- Two authoring gaps in item-0091, both caught only by the gate

Item-0091 (export enum constants; type the engine and carriage
discriminators) was authored by the analysis lane against anchor
`42acf91` and landed as two commits, `0f1e5a3` (commit 1: export
infrastructure and the engine discriminator) and `c46e619` (commit 2: the
ssh/https carriage consolidation). It is part of the type-cleanliness arc
that the 2026-07-07 dual-type-safety audit opened.

Two assertions in the pre-authored instruction were wrong at the anchor.
Both were byte-readable facts, not generator-internal ones -- neither
needed a spike. Both were caught by the execution gates rather than by the
analysis, and both belong to the residual-risk class the 2026-06
model-behavior retrospective assigned to the analysis role: errors in the
gates themselves.

## Gap 1 -- the export blast radius was measured incompletely

The instruction asserted that the `genenums` export rename touched exactly
one hand-written reference, the file-artifact-type comparison in
`internal/primitive/artifact_type.go`. At `42acf91` it touched two: that
site and `internal/lane/deploy_strategy.go`, whose `KubectlVerb` switch
referenced the unexported `DeployStrategy` constants.

The miss came from the measurement method. The spike measured the blast
radius with a single `go build ./...`. Go compiles in dependency order;
`internal/primitive` failed first, and `internal/lane` -- which imports it
-- was never compiled, so its broken reference was masked behind the
upstream failure. The build reported one undefined symbol; the real set
was two.

The commit-1 build gate caught it. The executor, applying the same rename,
hit the masked `lane` error and stopped per the instruction's explicit "if
any other undefined: appears, STOP" clause, then established the complete
set by grepping every generated constant against the whole tree -- exactly
two sites, no third.

Lesson: measure a global-rename blast radius by an exhaustive per-constant
grep against the whole tree, not by a single build. A build stops at the
first failing package and masks every reference in packages downstream of
it; a build is not a search. This sharpens the existing snapshot-hygiene
imperative ("scope the blast-radius search to the whole module, test/
included"): the completeness failure is not only about which directories
are searched but about the search mechanism.

## Gap 2 -- the exhaustive linter was mis-modeled

The instruction asserted that `cmd/strike/main.go`'s connection-type switch
"stays exhaustive-clean after the retype" -- three literal cases covering
all values, no default -- and told the executor to leave it untouched. At
`42acf91` this was false. Once `id.Connection.Type` became the named
`endpoint.EngineType`, the switch turned into a non-exhaustive finding: the
`exhaustive` linter matches cases by named enum member, not by underlying
value, so a bare `case "mtls"` literal does not register as covering the
member `EngineTypeMtls`. With no default, the linter reported all three
members missing.

The `make check` exhaustive gate caught it during commit 1. The fix
converted the three literal cases to the named constants, and `main.go` was
folded into commit 1 rather than deferred.

Lesson: typing a switched-on field pulls every switch and comparison over
it into the exhaustive ripple. The linter matches by named member, not by
value; a literal case does not count as covering the member it equals. So
every literal-cased switch over a newly-typed enum field must convert to
the named constants or carry a default, or the linter reports all members
missing. "All values covered by literals" does not satisfy exhaustive -- so
the anti-initiative note "leave it, it stays clean" was actively wrong;
leaving it would have kept `make check` red.

## Common thread

Both gaps were mis-modeled facts an unaided reading should have gotten
right: the build's masking behavior and the linter's matching rule. They
match the 2026-06 finding that the analysis role's residual risk is errors
in the gates themselves -- the pre-authored gate text asserted two false
things, and only the executor's independent gates (build ordering surfaced
one, the exhaustive linter the other) caught them. The countermeasure that
retrospective proposed -- dry-run a paper's quality-gate greps against its
own after-snippets -- would not have caught either, since these were
assertions about tool behavior, not grep contradictions. The applicable
countermeasure is the two lessons above, applied at authoring time.

## Landed state and open work

Item-0091 is complete at `c46e619`; both gaps were folded into commit 1
(`0f1e5a3`) with operator approval, not deferred. `make check` is green at
both commits and the attestation goldens are byte-identical.

The same named-discriminator pattern remains to be applied to the three
other struct-arm unions -- the trust anchor, the deploy method, and the
provenance source. That is roadmap item-0099 (proposed); its body carries
the exhaustive-ripple lesson as execution guidance.

## Promotion note

Lesson 1 is a candidate refinement of the snapshot-hygiene imperative in
`AI-REVIEW-AND-RETROSPECTIVES.md`. Lesson 2 is a candidate new imperative
for the authoring clauses in `AI-WORKFLOW.md`. Both are recorded here as
the empirical basis; promotion to an imperative is a separate,
operator-ratified step.
