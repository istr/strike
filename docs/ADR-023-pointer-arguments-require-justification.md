# ADR-023: Pointer Arguments Require Justification

## Status

Accepted.

## Context

Go does not have a non-null pointer type. Every `*T` is potentially
nil. The idiomatic Go default is to pass and receive structs by
pointer regardless of mutation, which leaves the question "can this
be nil here?" unresolved at every call site. For a security tool,
this nil-check ambiguity has three concrete costs:

1. Defensive code paths multiply. Each method on `*T` that wants to
   be safe needs a nil-check at the start.
2. Inconsistent nil-handling produces bugs that pass review. Some
   methods on a type guard against nil; others do not. The ones that
   do not get to "but the code never calls this with nil anyway"
   lasting until something does.
3. The contract is fuzzy. A function that takes `*T` could mean
   "this argument is required" or "nil means absent" depending on
   the author's intent that day.

A code review of the strike codebase identified three signatures
where the pointer carried no justification: small read-only structs,
no mutation contract, and no nil-as-signal. These cost code
(nil-checks, dereferencing syntax) without buying anything. As
values, the same signatures would be impossible to call with a nil
equivalent; the nil-handling discipline disappears at the type
level.

Go's idiomatic answer to the "non-null reference" gap in the
language is "pass by value". That is the default this ADR adopts.

## Decision

Struct arguments default to value semantics. Pointer is used only
when at least one of the following applies:

1. **Mutation through the argument is part of the contract.** The
   caller wants to see the change.
2. **The struct embeds a sync primitive, an `io.ReadWriter`, or
   another type that cannot be safely copied.** `go vet` will flag
   the copy.
3. **The struct is large enough that copying is a measurable cost.**
   Roughly, more than ~64 bytes of header (excluding contents
   reachable through reference fields like maps, slices, channels,
   strings).
4. **`nil` is a meaningful contract signal.** "Optional, nil means
   absent" or "feature disabled if nil".
5. **Interface satisfaction requires pointer receivers.**

The same rule applies to method receivers. Methods on `*T` are used
when the method mutates, when nil is a meaningful receiver, or when
the type embeds an uncopyable. Read-only methods on small structs
use value receivers.

This is a *default*, not an absolute. Existing pointer signatures
may be left alone when no concrete benefit comes from converting
them. In particular, types like `*lane.Step`, `*lane.Lane`, and
`*Attestation` are pointer-passed throughout the codebase by virtue
of category 3 (large structs); the rule does not call for changing
them.

The rule does not apply to return values. Returning `*T` for "found
this" vs nil for "not found" remains idiomatic and is unaffected.

## Consequences

- New pointer parameters require a justification matching one of
  the five categories. "It's how the rest of the function looks" is
  not a justification by itself; that maps to category 3 only when
  the size warrants it.
- AGENTS.md gains a "Pointer arguments" rule under Code style,
  restating this decision in operational terms for AI coding agents.
- Three current cases are addressed in this patch: `TLSConfig`,
  `*lane.DeploySpec` in two internal deploy helpers, and
  `*RekorClient` method receivers plus the internal helper
  `submitToRekor`.
- Public APIs where nil is a meaningful contract signal stay
  pointer-typed. Specifically: `executor.SignManifest`'s `rekor
  *RekorClient` parameter (nil = Rekor disabled); the `Deployer.Rekor`
  field (same); the `*Step.Deploy` and `*Step.Pack` lane fields
  (nil = step is not a deploy/pack step). These are category 4.

## Principles

- Code is liability (each pointer signature carries a nil-check
  obligation; eliminating unjustified pointers eliminates the
  obligation).
