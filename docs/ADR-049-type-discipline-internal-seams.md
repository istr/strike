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

## Amendment 2026-08-31 -- rule (4)'s worked site is renamed and closed

The rule (4) entry in Consequences names `transport.DialTCP` and
`transport.DialVerified`. Neither exists now. item-0088 retyped `DialTCP`
from a packed string to `netip.AddrPort`, closing the entry as written;
item-0130 then replaced `DialVerified` with `transport.DialResolved` and
unexported `DialTCP` into it, so the resolved destination and the
verification name are two parameters of one function and the foreign call,
`net.Dialer.DialContext`, sits one frame deeper.

Rule (4) itself is unaffected. The conversion is still owned at the foreign
call rather than at a judged boundary; `DialResolved` is where that call now
sits. The entry records where the tree stood when this ADR was written.

## Amendment 2026-11-01 -- generated enum constants are exported and named directly

Consequences left the visibility of the constants `genenums` emits open,
owned by item-0091. item-0091 settled it in `0f1e5a3` (2026-07-12) without
recording the outcome here: `genenums` emits exported constants, named
`<Type><Value>` (`CertificateModeLeaf`), and a consumer in any package names
them directly. The `exhaustive` linter checks every switch over such a type,
so a value added in CUE forces a case in Go. A discriminator of a
hand-written `@go(-)` union may carry a named type of its own definition and
use the same constants (`EngineType`, `CarriageType`).

This supersedes the earlier policy of the type-safety decision forks of
2026-07-09: unexported constants reached only through a method of the
owning package, and discriminators left as literals. The one method of that
form, `primitive.FileArtifactType.IsFile`, is removed in the same change;
its two callers compare with `primitive.FileArtifactTypeFile`.

## Amendment 2026-11-14 -- (6) a required collection is non-empty

This amendment adds rule (6) to the Decision. Rules (1) through (5) and the
earlier amendments stand unchanged.

### (6) A required collection is non-empty

In CUE an open list (`[...T]`) and a struct made only of pattern constraints
(`{[K]: V}`) carry an implicit empty default. A regular field of either form
reads as required, but validation never requires it: a value that omits the
field validates, the exported JSON Schema leaves it out of `required`, and the
omission surfaces at run time, if at all. Inside a definition, therefore:

- a list field is either optional (`field?: [...T]`) or non-empty
  (`field: [T, ...T]`);
- a map field made only of pattern constraints is optional
  (`field?: {[K]: V}`);
- neither carries the required marker `!`, which accepts an empty list as
  present.

The rule reaches every field inside a definition, nested ones included. A
field outside a definition carries data, not schema -- the trust-layer
classification declares the pattern and the entries of each of its maps in two
declarations -- and the rule does not reach it. The value of a pattern
constraint (`[K]: [...T]`) is the type of each entry, not a field, and is not
reached either.

With the rule, the schema carries the protection a runtime guard would
otherwise repeat, and code after parsing keeps no guard for a shape the schema
rejects. `go tool lintcue -contract` mechanizes the rule as
`required-collection`.

Applied when the rule lands: the capture command, the SSH host keys, the four
lists of the inline trust root, and the certificate chain of a trust-root
authority are non-empty; the step's args, env, inputs and secrets, the pack
spec's files, a capture set's captures, the lane's secrets and a step result's
outputs are optional. The cross-validation vectors follow the boundaries they
check and make all of theirs optional, since each has a defined empty case.
`contract/attest` is frozen for the beta line, so each of its nine sites
changes only as a ratified freeze event; until then each is a deferral the
lint names field by field, and a deferral that no longer matches a field is a
finding of its own.

## Amendment 2026-11-14 -- rule (6) reaches the fields of a pattern's entries

Rule (6) says that the value of a pattern constraint is not reached. The
sentence concerns the value itself, the type of each entry: in `[K]: [...T]`
the open list is not a field and carries no default of its own. When the value
is a struct, its fields are fields of every entry, and rule (6) reaches them as
it reaches any field inside a definition: in `m?: {[string]: {x: [...T]}}`, `x`
is a required open list. Every other clause of rule (6) stands unchanged.

## Amendment 2026-11-20 -- (6) and (7): no field holds an empty value, and one statement has one form

This amendment generalizes rule (6) of the amendment of 2026-11-14, adds
rule (7) and sharpens rule (1) for the values it governs. Rules (2)
through (5) and the earlier amendments stand unchanged.

Rule (6) closed one half of a confusion and left the other. A required
collection had to be non-empty, but an optional one could still be empty,
so "nothing" kept two forms: an absent field and an empty one. A string
field accepted the empty string beside its absence, and the value of a
pattern constraint was not reached at all. Each such pair leaves a reader
of the wire to guess what an empty value was meant to say.

### (6) No field holds an empty value

A field is a named member of a struct, whether declared or matched by a
pattern: a key of a map is a field. A list element is not a field. Inside
a definition:

- no field holds the empty string, `null`, the empty list or the empty
  struct;
- a required field holds a non-empty value, and an optional field is
  either absent or holds a non-empty value.

The rule reaches every field at every depth, the entries of a pattern
included: in `env?: {[string]: string}` the key `FOO` of `{FOO: ""}` is a
field that holds the empty string, and the value is invalid. A variable
that must be empty is not declared. A list element is free within its
type: `["", ""]` is a non-empty list.

The rule judges the value as the author writes it, not the value that
evaluation produces once defaults are filled in: no author can write the
evaluated value. Rule (7) closes the one place where the two differ.

Each admissible choice has exactly one form, whether the field is
required or optional (`?`):

| Kind | Form |
|---|---|
| string | `string & !=""`, or a grammar that excludes the empty string |
| list | `[T, ...T]` |
| map made only of pattern constraints | `{[K]: V} & struct.MinFields(1)` |
| struct whose fields are all optional | `#T & struct.MinFields(1)` at the field that uses it |

`struct.MinFields` stands at the field, never in the definition of the
struct: there it makes the generated Go type `any` and drops the
closedness of the exported schema. A field that carries it names its Go
type explicitly, `@go(Name,type=map[K]V)` for a map and
`@go(Name,type=*T)` for an optional struct; `optional=nillable` combined
with `type=` drops the pointer. The required marker `!` is no form of
non-emptiness: it accepts an empty list as present.

### (7) One statement, one form

Every statement a value makes has exactly one form, and the validator
rejects every other form.

- **A field with a default** is a regular field whose default arm is
  explicit and whose type follows the default: `forceRun: *false | bool`.
  An optional field never carries a default, and no default is resolved
  in Go behind an optional field. In an input such a field has three
  forms, and they are three statements: omitted, the default applies;
  the default written, the value is pinned against a later change of the
  default; any other value. This is the form the amendment of 2026-09-06
  to [ADR-056](ADR-056-tls-trust-anchor-as-inline-certificate.md) chose
  for the certificate mode.
- **No struct-valued field accepts `{}`.** Written `{}`, a struct whose
  fields are all optional, or whose fields evaluate without input, would
  be empty as written and non-empty as evaluated, and rule (6) could not
  be kept in a form the validator checks. A struct whose fields are all
  optional therefore carries `struct.MinFields(1)` where it is used. That
  validator counts the evaluated fields, defaults and constants included,
  so a struct with a defaulted or a constant field holds at least one
  field the instance must write. A field typed with a union of named
  definitions already rejects `{}`.
- **A discriminator is written.** A field typed with a discriminator
  vocabulary -- the deploy method, carriage, engine and credential types
  -- carries the required marker, as in `type!: "registry"`, in the arm
  of a union and in a single struct that seeds a later union alike. A
  constant that discriminates nothing stays without the marker and
  follows the rule for a field with a default.
- **A grammar with an implied default writes it implied.** An authority
  or URL never spells out the default port of its scheme. `#Address`, the
  Go projection of that grammar, keeps its port optional: there, absence
  is the one form of the default port, not a default resolved behind a
  field of an input.

### What the rules do not reach

Two values of type `_` stand for content the contract does not own. They
are exempt by this closed list:

- the open remainder (`...`) of `#CycloneDXDocument`, the predicate of
  the SBOM statement of
  [ADR-059](ADR-059-sbom-sealed-digest-and-signed-statement.md), whose
  content the CycloneDX specification governs;
- `#AttestationVector.inputs.attestation`, the input of a
  cross-validation vector, which must also carry invalid attestations to
  show that they are rejected.

Any other value of type `_` is a defect.

### (1), sharpened: an entry parser rejects a set but empty value

The owning parser of rule (1) holds the input it parses to rule (6). A
value that is set but empty -- an environment variable set to the empty
string, an empty flag value, an empty secret source -- is malformed and
is rejected with the name of its source. A value that must be absent is
left unset.

### Mechanization and application

The contract mode of `go tool lintcue` checks rules (6) and (7) by
evaluation, not by syntax: every field of every definition, the entries
of a pattern included, is unified with each of the four empty values, and
a value the validator accepts is a finding. This replaces the syntactic
check of the amendment of 2026-11-14. A union is not entered: each of its
arms must be a named definition and is checked as one, and the field
that uses the union is checked like any other field. The tier check
admits one import from outside the contract, the standard package
`struct`. A site that does not yet hold the rules is a deferral the lint
names field by field, and a deferral that no longer matches a field is a
finding of its own.

Applied when the rules land, beyond the forms above: the lane's timeout
is a field of the lane with the default `"10m"`, and the separate block
of lane defaults and its fallback in Go go; the state recording of a
deploy is optional, absent meaning no recording, its pre-state and
post-state are optional, and a capture set that is present holds at
least one capture; the port of the DoT resolver is a field with the
default 853. `contract/attest` is frozen for the beta line: its sites
change only as a ratified freeze event, and until then each is a
deferral. A narrowing in a package that `contract/attest` imports reaches
the attest wire as well and is a freeze event of its own.

**Supersedes, in rule (6) of the amendment of 2026-11-14:** "a list field
is either optional (`field?: [...T]`) or non-empty (`field: [T, ...T]`)"
is read as: "a list field is non-empty (`[T, ...T]`), optional or not";
"a map field made only of pattern constraints is optional
(`field?: {[K]: V}`)" is read as: "a map field made only of pattern
constraints is non-empty (`{[K]: V} & struct.MinFields(1)`), optional or
not"; "The value of a pattern constraint (`[K]: [...T]`) is the type of
each entry, not a field, and is not reached either." is read as: "Each
entry of a pattern constraint is a field and is reached."; and "make all
of theirs optional, since each has a defined empty case" is read as:
"express each defined empty case as an absent field". **In the second
amendment of 2026-11-14,** the reading that the value of a pattern
constraint is not reached is withdrawn; its reading that the fields of
an entry's struct are reached stands.

## Amendment 2026-11-21 -- no definition reaches itself or carries a default

This amendment adds two rules to rule (7) of the amendment of
2026-11-20 and states which rules the lint checks on the written form.
The earlier amendments stand unchanged.

### No definition reaches itself

CUE admits a definition that names itself when the recursion ends in a
branch that does not recur, as in `#List: {head: _, tail: null | #List}`.
The contract has no use for one, and over a recursive definition the
walk of the lint through the evaluated value would not end. No
definition of the contract reaches itself, by a reference, a composition
(`#T & {...}`) or an embedding, directly or through other definitions.

### No definition carries a default

The one form of a value with a default is the default arm at a regular
field (rule (7)). A definition whose own value carries a default arm, as
in `#Port: *443 | int`, would hand the default to every field that names
it: a second form of the same statement, and at an optional field a
default the field does not show. No definition carries a default arm of
its own.

### What the lint checks on the written form

Rule (6) judges the value as the author writes it, and the lint checks
it by evaluation. Three rules it checks on the written form, because the
evaluated value does not show them: an optional field carries no
default, no definition carries one, and no definition reaches itself.
Evaluation gives every open list an implied default and drops a default
arm that another arm subsumes, so it cannot tell a written default from
none. The reference that closes a cycle is an identifier that names a
definition of its own package; an identifier qualified by an import
names a package of a lower tier, which cannot name the first one back.
While any definition reaches itself, the lint reports it and does not
walk the evaluated value, so the walk always ends.
