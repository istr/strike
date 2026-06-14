# Working With AI: Collaboration Practices

strike is built in an AI-heavy workflow. An operator works with a
general-purpose language model to do architectural analysis and to
author instruction files; a separate coding agent executes those
instructions against the codebase. This document records the
collaboration practices that have proven effective and the reasoning
behind each one.

It is deliberately distinct from its neighbors:

- `DESIGN-PRINCIPLES.md` states the axioms of the *product*.
- `AGENTS.md` gives imperative rules to the *coding agent*.
- `CONTRIBUTING.md` defines review criteria for *changes*.
- This document describes how the *human-AI loop itself* is run.

None of the practices below is aspirational. Each was adopted after a
concrete failure mode made its absence visible.

## Roles in the loop

The loop has three roles with a strict direction of authority:

- **Operator.** Owns scope and ratified decisions. Approves every schema
  or structural decision before any instruction is written. Ratified
  decisions (the `D`-numbered list) and ADR text are permanent: they are
  annotated, never silently rewritten.
- **Analysis model.** Reads the codebase, produces architectural
  analysis, and authors instruction files. Proposes decisions; does not
  ratify them.
- **Coding agent.** Executes instruction files. Does not infer scope,
  does not expand it, and stops and asks when an instruction does not
  match the tree.

The direction matters: analysis flows up to the operator for
ratification, instructions flow down to the coding agent for execution.
Neither model decides scope on its own.

## The instruction file is a contract

Work reaches the coding agent as a numbered instruction file, not as a
conversational request. Each file follows the same shape:

- **Goal** -- one paragraph stating the end state.
- **Out of scope / do NOT touch** -- an explicit boundary list.
- **Confirmation gate** -- the schema or structural decisions that must
  be ratified first, plus the working-tree hash the before-snippets were
  taken from.
- **Anti-initiative clause** -- the things the agent must not do even if
  they look helpful.
- **Files and edits** -- exact before/after snippets, not deltas or
  templates. The agent handles "replace this exact text with that exact
  text" far more reliably than "make this kind of change".
- **Quality gates** -- the `grep` and build/lint/test commands that must
  pass, written so the result is checkable rather than asserted.
- **Acceptance criteria** and a **commit message**.
- **Execution profile** -- the recommended model class and reasoning
  depth for executing this instruction, with a one-line rationale.

The exactness is the point. A before-snippet that does not match the tree
triggers a stop-and-report instead of an improvised edit, which converts
"the tree drifted since this was written" from a silent corruption into a
caught error. Pinning the before-snippets to a named working-tree hash
turns the project's own determinism discipline inward onto its
development process.

Two corollaries earned in practice. First, a before-snippet has to be taken
from the pinned tree itself, not from a working copy or an upload that predates
the pin. When earlier, not-yet-pushed work has reformatted a file, an upload of
it can differ from the tree in whitespace alone, and a byte-exact snippet cut
from the upload then fails to match for a reason that has nothing to do with
drift -- noise that trains the agent to treat stop-and-report as a false alarm.
Pin the snippet to the named hash, or have the agent re-read the file at that
hash before applying.

Second, an acceptance check has to be scoped to what was removed, not to a
token. When a deleted path and a retained path share a term -- a keyed path and
a keyless path both naming `hashedrekord`, say -- a blanket "this grep returns
nothing" criterion cannot pass without cutting code that was meant to stay.
Write the criterion against the deleted artifact (a removed type, a deleted
file), and treat a criterion that can only be satisfied by touching retained
code as a defect in the criterion, to be surfaced by the agent rather than
satisfied by it.

Instruction files are ephemeral working papers, not tracked history. They
exist to move one change from analysis to execution and are discarded once
it lands; their numbering carries no meaning and need not be contiguous or
even consistent. This is the opposite of an ADR, which is permanent,
strictly monotonic, and never renumbered. Nothing downstream may depend on
an instruction file's name or number.

## The execution profile is part of the contract

Choosing which model executes an instruction, and with how much reasoning
budget, used to be implicit operator judgment at launch time. The profile
section makes it explicit: the analysis model, which knows the
instruction's risk class better than anyone at the moment of writing,
records a recommendation in the file itself -- model class, reasoning
depth (none / brief / deep), and one line of why.

The mapping follows risk, not size. Mechanical work -- byte-exact snippet
application, documentation, fixture churn behind count gates -- needs the
smallest capable model and no deep reasoning; the gates carry the safety,
and a stronger model adds cost and initiative surface, not quality. Code
changes verified by hermetic gates sit in the middle. The strongest model
with deep reasoning is reserved for instructions whose acceptance includes
live verification, debugging against a running system, schema-and-codegen
chains, or cross-cutting removals -- the classes where execution has
historically required diagnosis, not just application.

The profile is advisory to the operator and is not a control. Gates,
before-snippets, and stop-and-report apply identically under every
profile; a stronger model is never a license to loosen them, and a weaker
model is never an excuse for a gate to fail. The profile's value is the
inverse: when an under-profiled session starts grinding against its gates,
the mismatch is visible and named instead of diagnosed after the fact.

## Decisions are ratified before instructions exist

Schema and structural decisions are resolved with the operator and
recorded (as `D`-numbered decisions) before any instruction that depends
on them is authored. An instruction never carries an unratified schema
choice. This is the same invariant `AGENTS.md` and `CONTRIBUTING.md`
state for the codebase, applied to the authoring step: the decision is
made by the operator, not discovered by the agent mid-edit.

## Anti-initiative is structural, not advisory

General-purpose models exhibit a documented bias toward doing more than
asked: migrating a config silently, adding a helper before confirming the
need, deleting a package instead of wiring it. The countermeasure is not
a reminder; it is structure. Every instruction carries an explicit
out-of-scope list and an anti-initiative clause, and substantive steps
end in stop-and-report gates. The finest-grained form of the rule appears
in documentation work: annotate, do not rewrite, because ADR numbering
and ratified text are permanent.

## Cluster by risk, not by finding order

When a review produces many findings, group them by risk before
sequencing the work. Documentation-only patches bundle into a single PR,
because they share one review concern ("make the docs match the code")
and bundling saves a review cycle per finding. Substantive changes -- the
ones that touch schema, types, or behavior -- stay separate and cautious,
one concern per PR.

## Removal is the default resolution

When a finding can be resolved either by implementing dead surface or by
removing it, removal is the default. Dead schema fields, unreferenced
config branches, and capabilities that are documented but not wired are
their own liability class: they invite an author to set a field that does
nothing. The bias toward removal is the operational form of "code is
liability" applied to review findings.

## Neutral checkpoints

Periodically commission a review from a fresh, context-free model session
that has only the code snapshot and the stated principles -- no project
memory, no prior framing, no investment in earlier decisions.

A context-free reviewer is valuable precisely because it has not
internalized what the working sessions "meant". The gaps it catches are
the aspirational-vs-as-built kind that context-rich sessions normalize: a
bootstrap lane that is documented but does not parse, a decision record
that still claims a phase the code has moved past, trust anchors that are
recorded in an attestation but not enforced at the connection layer. A
session that knows the intent reads past these; a session that knows only
the artifact does not.

The neutral review is a checklist to verify, not a verdict to apply. It
should disclaim its own authority -- a single read of a snapshot can be
wrong about the working tree -- and every finding is validated against
the live tree before any instruction is written. That disclaimer is part
of why the practice works: it produces candidates for confirmation, not
commands.

## Retrospectives with the model

After a large change-set lands, run a structured retrospective: have a
model re-read the change-set against the original review or spec and
report what is resolved, what remains, and what patterns emerged.

The value is threefold. It converts scattered PR history into an explicit,
checkable status ("of N findings, these are verified fixed, these are
deferred, this one is open"). It verifies fixes against the actual tree
rather than against the intent of the instructions that produced them. And
it distills the working method itself into reusable form -- this document
is an output of one such retrospective.

A retrospective also surfaces residue that no single PR owned: a
deprecated form that survived only in test helpers, or a track that was
deliberately deferred and should be stated as deferred rather than left
implicit. Those are invisible from inside any one PR and obvious from a
read across all of them.

## Snapshot hygiene

The neutral checkpoint and the retrospective are only as good as the
snapshot they read. An early snapshot configuration excluded all `*.md`
files in order to filter out the instruction files, and in doing so hid
the project's own documentation from the first review -- so the
documentation-drift findings could be planned but not verified against
the snapshot. The lesson: the snapshot must contain everything the review
reasons about, and exclusions must be surgical (exclude the instruction
files by path, not all markdown by glob).

The same completeness applies to the searches run against the snapshot, not
only to its contents. A removal arc enumerated the callers of a changed
function signature by grepping `internal/` and `cmd/` and leaving out `test/`;
the three integration-test callers it missed compiled only because the coding
agent re-derived them at execution time, not because the instruction listed
them. The lesson generalizes the one above: scope a blast-radius search to the
whole module, `test/` included, because integration tests call production APIs
exactly as production code does.

A complementary structural check removes the dependence on a human
reading the snapshot at all: compare `ls docs/ADR-*.md` against
`ADR-INDEX.md` in CI, so an ADR that exists on disk but is missing from
the index fails the build instead of waiting for the next review.
