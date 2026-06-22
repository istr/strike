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
  ratify them. Grounds by reading, not by running (see below).
- **Coding agent.** Executes instruction files. Does not infer scope,
  does not expand it, and stops and asks when an instruction does not
  match the tree.

The direction matters: analysis flows up to the operator for
ratification, instructions flow down to the coding agent for execution.
Neither model decides scope on its own.

## The analysis model grounds by reading, not by running

The analysis model is deliberately tooling-minimal. It has git-native read access
to the pinned tree, text search, and the planning script -- enough to read any
file at a named hash, confirm a string's shape and count, and move a roadmap
item. It does not have the build, test, or codegen toolchain, and that absence is
a design choice, not a gap: the model that authors instructions stays in the
read-reason-author lane, and the build-and-run lane belongs to the coding agent
alone. Narrowing what the author can do narrows what an over-eager author can
quietly get wrong.

This splits grounding questions into two kinds. A *static* question is settled by
reading the pinned source: whether a before-snippet appears exactly once, where a
base/wire boundary actually falls in a file, whether a generated artifact is
gitignored, what a function does to a given input. The analysis model answers
these itself; they are the substance of grounding. A *dynamic* question needs the
toolchain to run: whether a code generator reorders its output after a file move,
whether a golden is byte-identical after a rename, whether `make check` passes.
The analysis model does not run these, and does not present a guess about one as
if it had measured it.

A dynamic question that bears on an instruction's correctness is resolved one of
two ways, chosen by a single test -- can a careful reader determine the outcome
from the pinned source alone? When yes, the instruction predicts and gates: it
states the expected outcome explicitly and makes the agent's own build/test gate
the proof, so a deviation stops the run instead of shipping. When no -- the
outcome is generator-internal or otherwise unreadable from source, and
load-bearing -- the measurement is delegated: the agent runs the operation in a
throwaway worktree and reports the result, and the byte-exact steps that depend
on that result are authored only afterward. The measurement is scratch, never
committed. The discriminator is whether the byte-exact content depends on the
measured value (delegate as a separate step) or only the gating does (predict,
and gate); confidence is not the test, since a guess dressed as a prediction
still ships unverified.

This was made explicit after a handover phrased a pre-authoring measurement as
something the analysis model would run in a scratch clone -- which it cannot and,
by design, should not. An instruction resting on a measurement its author could
not take is either a fabrication or an unverified guess wearing a measurement's
clothes; both are worse than a named hand-off. Stating the boundary turns "I
can't run this" from an apology into a defined step in the loop.

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

## Planning state lives in the roadmap item store, never in the chat

The analysis model tracks planning state through exactly one mechanism: the
checked-in `roadmap/` item store -- one markdown file per work item, managed
through the `roadmap-items` skill. There is no second place. The prose
`docs/ROADMAP-*.md` files this section once named have been retired; their open
work was migrated into `roadmap/` items and the files removed with `git rm`.
The moment a planning effort needs structure -- a sequence of arcs, a status
flip, a checklist of findings, a "landed vs open" ledger, or a cross-arc
execution order -- that structure is an item (or a re-rank, or a `_order.md`
edit) in the store, not prose maintained in the conversation. Planning that
lives only in the chat transcript, in a handover note, or in an upload is not
tracked; it is in flight and one compaction away from loss.

The store holds only drift-invariant planning state: each item carries a
`goal`, an `acceptance_intent`, and `links`, never byte-exact snippets, exact
file-and-edit lists, or grep gates -- those are authored ephemerally at
execution time against the then-current pin and discarded after they land. An
item moves `proposed -> ratified -> done`; `proposed` is all the analysis model
writes, the `proposed -> ratified` flip is the operator's call riding along
with the ratifying commit, and a `done` item moves to `roadmap/completed/` so
the active set stays small. This is the complement of the ADR convention's
archival rule: the store is not only where finished planning is retired, it is
where planning is born -- nothing is tracked anywhere else first.

The query path is the point. "What is open in arc X by rank", "what runs next",
"landed vs open" are answered against the checked-out tree through the skill, not
reconstructed from prose. Handover notes and retrospectives may summarize the
backlog and point at items by id, but they do not own the tracking. When a
handover or a chat starts enumerating open work under its own labels, that is the
signal an item is missing or stale, and the fix is to write it into the store --
not to let the labels accrete in prose. This is the same single-sourcing the
product applies to meaning: the store is the one definition of what is planned,
and every other document refers to it rather than restating it. ADRs and
`D`-numbered decisions are the exception in the other direction: they are
permanent, append-only, live outside the store, and are never edited through it.

The cost of getting this wrong has already been paid: a context compaction that
blurred an iterative arc sequence, leaving a handover to reconstruct
landed-vs-open state from a transcript because it had never been committed to a
roadmap. An item in the store is grounded, diffable, reviewable in a PR, and
survives the session boundary; a chat-resident plan is none of these.

## Code comments never leak the workflow's transient vocabulary

The planning store, the instruction files, and the chat transcript are all
*scaffolding*: they exist to produce a ratified change and then fall away. The
code that lands is the durable artifact, and it must stand on its own. So a
comment authored during this loop must not reach back into the scaffolding it
came from. Forbidden in any code or CUE comment: a roadmap item id or arc name,
an instruction-file reference, a historical note about how the code got here,
and a category that only ever existed in the conversation -- the canonical
example being "layer 1 / layer 2", which is precise in an ADR-046 discussion and
meaningless to someone reading the file cold. The one durable cross-reference a
comment may carry is an ADR (`docs/ADR-NNN-...`): architectural *why* has a
single permanent home, and the comment points there instead of restating a label
that will not survive the session.

This is a direct consequence of the two-role split. The analysis model writes an
instruction against a store item and a live transcript, where "item-0016" and
"the layer-2 split" are unambiguous; the executor then bakes a comment from that
same vocabulary, and it ships -- now permanently bound to context the reader
will never have. The author who has the context is exactly the one who cannot
tell the comment is unmoored. The discipline therefore lives in the
instruction's acceptance criteria, not in the executor's judgement: a comment is
written to be read from a clean checkout, and the operationally enforced form is
`docs/CODE-STYLE.md#self-contained-comments` (which `AGENTS.md` makes an
imperative for the coding agent).

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

## Inspect the whole file, never a ritual window

Both sides of the loop share a failure: inspecting a file through an arbitrary
line window -- `sed -n 'A,Bp'`, `head`, `tail` -- as the way to find out what the
file contains, rather than to read a region already located. The window is a
guess about where the answer lives, committed before the answer's location is
known, and when the guess is wrong the output does not announce its
incompleteness: a truncated slice of a target list looks exactly like a complete
target list, so a wrong window becomes a confident "it is not there." A line
window is a declaration about where to observe, and a negation drawn from a
declaration is the move the product's "observation defeats declaration" principle
forbids -- here turned inward on the development tooling.

The habit is a borrowed idiom, not a reasoned choice. The shell examples the
models learned from window files because scrolling a terminal is tedious, an
ergonomic reason with nothing to do with an agent reading a file into context;
the surface form survived and its rationale did not. On a small file the
windowing saves no meaningful context and buys an unbounded correctness risk, and
because the risk is invisible at the moment it is taken, the feedback that would
retire the habit rarely arrives.

The concrete failure that fixed this as a rule: an analysis session concluded
that a harness Makefile target did not exist by reading a window that ended a few
lines above the target's definition, asserted the absence, and was corrected by a
whole-file grep the operator ran. The target had been there throughout, named in
the `.PHONY` line the window also cut off.

The rule -- stated imperatively for the agent in AGENTS.md and as practice here
-- is that an existence or absence claim rests on a whole-file search (`grep -n`
over the whole file) or a full read, never on a slice. A line window is
legitimate only after a search has located the target and only to read the
surrounding context the search cannot give cleanly: prefer
`grep -n -C3 PATTERN file`, where the match anchors the window, over a
hand-guessed `sed -n 'A,Bp'`, and reserve the bare span for when a prior grep
already supplied line A. It is the same discipline the snapshot-hygiene lesson
applies to blast-radius searches -- scope the observation to the whole artifact,
because what you are looking for is exactly as likely to sit outside your window
as inside it.
