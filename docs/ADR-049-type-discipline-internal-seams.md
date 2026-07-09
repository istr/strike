# ADR-049: Type discipline at internal seams -- grammar operations, wire projections, and boundary determination

## Status

Accepted. Concretizes [ADR-048](ADR-048-contract-type-semantics.md): where
ADR-048 says a concept is representation-neutral and its wire forms are
projections, this ADR says where a projection is defined, what a grammar
operation returns, and when an internal signature stops being internal. Sharpens
the `type-conversion-ownership` clause of `docs/CODE-STYLE.md` from conversion
sites to signature design.

## Context

A dual type-safety audit ran the same survey over the same pinned tree through
two harnesses. Four clusters ended in disagreement, and in each case both lanes
were right about a different half of the question, because no rule existed to
cite. The disagreements were not about facts; they were about which fact
decides.

The adjudicated verdicts are recorded in
[docs/TYPE-SURVEY-RULEBOOK.md](TYPE-SURVEY-RULEBOOK.md), which owns the
classification rules and may be revised as the survey practice evolves. What
follows here are the four architectural rules those verdicts generalize to, plus
one contract-shape rule that a generator limitation forces. These are permanent.

## Decision

### (1) No contract type without wire existence

A value that enters the process from its environment and never serializes is not
a contract concern. It gets exactly one owning parser at its point of entry, and
every consumer downstream receives the parsed result. A second inspection of the
same raw input -- a second prefix test, a second split, a second reconstruction
of a form the first inspection already knew -- is a defect of the parser's
absence, not evidence that a type is missing.

The corollary is that a missing type and an unowned parse are different findings
with different remedies. When the target forms are already modelled, only the
discrimination between them is unmodelled, and the remedy is a parser, not a
definition in `contract/`.

### (2) Wire projections belong to the defining package

A method that converts a concept value into a foreign grammar -- a packed
authority, a URL, a `known_hosts` host field -- is defined in the package that
defines the concept. That a projection produces a grammar the package's other
projections do not produce is the reason it is its own method, not a reason to
site it elsewhere.

A projection written outside the owning package necessarily performs named-type
conversions on the concept's fields at a distance. The `linttypeconv` allowance
for named assignments makes that pass the linter; it does not make it correct.

### (3) A grammar operation returns its grammar

A method whose result is still a member of its receiver's grammar returns the
receiver's type. Cleaning an absolute canonical path yields an absolute
canonical path; taking its directory yields one; testing containment takes one.
Returning `string` from such a method is an unapplied type at the definition
site, and it propagates: every caller is forced into string handling, and the
predicate the method should have owned is re-implemented once per consumer.

`String()` is the single named exception, because `fmt.Stringer` is a foreign
interface and the value it produces is a message, not program state.

The discriminator against rule (2) is the grammar, not the direction: an
operation stays inside the type's grammar, a projection leaves it. Both are owned
by the defining package.

### (4) The boundary is the foreign call, not its shape

A strike-internal function is a boundary only when it is itself the call into
foreign code. Resemblance to a foreign idiom confers no boundary status. A
wrapper whose parameter imitates the shape its callee will eventually need,
while its sibling in the same package takes the typed value, is an unapplied
type; the boundary is one frame deeper, at the foreign call, where the
projection belongs by rule (2).

### (5) String disjunctions in the contract are named definitions

Every string disjunction in `contract/` is a named definition
(`#Name: "a" | "b"`), referenced by the fields that carry it. An inline
disjunction in a struct field is not permitted.

The reason is mechanical: `tools/genenums` recovers a disjunction's values as
Go constants through the public CUE API, and it can only find them under a named
definition. An inline disjunction generates a bare `string` field whose admissible
values exist nowhere in Go, so no switch over it can be checked for
exhaustiveness.

A struct union whose arms each carry a single concrete discriminator literal
(`#EngineUnix: {type: "unix"}`) is structurally different: the disjunction is
over the arms, not over the field. Rule (5) does not reach it.

## Consequences

The tree violates rules (1) through (5) at the sites the audit found. This ADR
lands ahead of the remediation, deliberately: the rules gate the design of the
fixes. Each violation carries its owner.

- Rule (1): the engine address is scheme-inspected three times
  (`internal/container`). Owner: item-0086.
- Rule (2): the `known_hosts` host projection lives in `internal/executor`
  while the concept lives in `internal/endpoint`. Owner: item-0087.
- Rule (3): three path grammar methods return `string`, three more are dead, and
  the containment predicate exists twice. Owner: item-0079.
- Rule (4): `transport.DialTCP` takes a packed string while `transport.DialVerified`,
  its sibling, takes the concept. Owner: item-0088.
- Rule (5): five inline string disjunctions remain in `contract/`. Owner: item-0090.

Rule (5) does not by itself make a discriminator usable outside its package:
`genenums` emits unexported constants. Whether that visibility is correct is an
open question with its own owner, item-0091. Until it is settled, a consumer
outside the defining package switches on the field's named type without named
constants.

Rule (2) applied to the observed engine identity exposes a hand-written mirror
of a generated union (`container.ConnectionInfo`). Collapsing it is item-0092.

## Principles

- **CUE first** -- rule (5) keeps the contract the single source of the value
  vocabulary by making every disjunction reachable to the generator; rule (1)
  keeps values that were never contract values out of it.
- **Meaning is single-sourced** -- rules (2) and (3) give every grammar exactly
  one home: the package that defines the type owns both the operations that stay
  inside its grammar and the projections that leave it.
- **Enforcement is structural** -- rule (4) replaces a judgement ("is this a
  boundary?") with an observation ("is this the foreign call?"), and rule (3)
  makes the containment predicate a property of the type rather than a
  convention each caller re-derives.
- **Code is liability** -- the rules delete more than they add: three dead path
  methods, two duplicate containment predicates, two redundant scheme
  inspections, one packed-string round trip.
