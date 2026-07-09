# Working With AI: Collaboration Practices

strike is built in an AI-heavy workflow: an operator works with a
general-purpose language model to do architectural analysis and author
instruction files; a separate coding agent executes those instructions against
the codebase. This file is the *imperative* half of that loop -- the rules the
operator and the analysis model obey at every anchor. Its neighbors:
`DESIGN-PRINCIPLES.md` states the axioms of the *product*, `AGENTS.md` gives
imperative rules to the *coding agent*, `CONTRIBUTING.md` defines review
criteria for *changes*, and `AI-ORCHESTRATION.md` explains the orchestrate-only
model these rules implement and records where each one came from. No practice
here is aspirational; each was adopted after a concrete failure, written down
in `docs/retrospectives/`.

## Where a rule lives

One placement rule governs the three workflow documents, and is stated only
here:

> If the executor or the author must obey it at every anchor, it lives in
> `AGENTS.md` (executor imperatives) or `AI-WORKFLOW.md` (loop imperatives)
> -- terse, imperative, one line of rationale, stable section anchors. If it
> explains, narrates, generalizes, or records history, it lives in
> `AI-ORCHESTRATION.md`.

Both imperative files are read whole at every anchor, so both stay under the
read-at-once limit. A rule that grows a backstory sheds the backstory to the
concept paper and keeps a pointer; it does not grow in place.

## Roles in the loop

Three roles, with a strict direction of authority:

- **Operator.** Owns scope and ratified decisions. Approves every schema or
  structural decision before any instruction is written. Ratified decisions
  (the `D`-numbered list) and ADR text are permanent: annotated, never
  silently rewritten.
- **Analysis model.** Reads the codebase, produces architectural analysis,
  authors instruction files. Proposes decisions; does not ratify them. Grounds
  by reading, not running (below).
- **Coding agent.** Executes instruction files. Does not infer or expand
  scope, and stops and asks when an instruction does not match the tree.

Analysis flows up to the operator for ratification; instructions flow down to
the agent for execution. Neither model decides scope on its own.

Roadmap item *creation* is the analysis model's lane, in the
read-reason-author session: it runs the roadmap-items skill to write the new
`proposed` item and delivers it as a git-am patch alongside the motivating
instruction. Every other roadmap-store mutation -- a `done` retire, a rank,
rescale, restructure, reorder, or `_order.md` edit -- is the executor's lane,
committed in the run that occasions it (a retire rides at the head of the next
instruction, a reorder rides with the work that reorders it). The operator
performs the `proposed -> ratified` flip between the two. This mirrors the
read-reason-author versus build-and-run split.

## The analysis model grounds by reading, not by running

The analysis model is deliberately tooling-minimal: git-native read access to
the pinned tree, text search, and the planning script. It has no build, test,
or codegen toolchain, and does not acquire one.

A *static* question is settled by reading the pinned source -- whether a
before-snippet appears exactly once, where a base/wire boundary falls, what a
function does to an input. The analysis model answers these itself; they are
the substance of grounding.

A *dynamic* question needs the toolchain to run -- whether a generator reorders
output after a file move, whether a golden survives a rename, whether
`make check` passes. The analysis model does not run these, and never presents
a guess about one as if it had measured it. Each load-bearing dynamic question
takes exactly one of two paths:

- **Predict and gate** when a careful reader can determine the outcome from
  the pinned source. The instruction states the expected outcome and makes the
  agent's own build/test gate the proof.
- **Delegate the measurement** when the outcome is generator-internal or
  otherwise unreadable. The agent runs the operation in a throwaway worktree
  and reports the result; the byte-exact steps that depend on it are authored
  only afterward. The measurement is scratch and is never committed.

The discriminator is whether the byte-exact *content* depends on the measured
value (delegate) or only the *gating* does (predict). Confidence is not the
test. Why: `AI-ORCHESTRATION.md#grounding-predict-and-gate-or-delegate-the-measurement`.

## The instruction file is a contract

Work reaches the coding agent as a numbered instruction file, not a
conversational request. Each file follows the same shape:

- **Goal** -- one paragraph stating the end state.
- **Out of scope / do NOT touch** -- an explicit boundary list.
- **Confirmation gate** -- the schema/structural decisions that must be
  ratified first, plus the working-tree hash the before-snippets were taken
  from.
- **Anti-initiative clause** -- what the agent must not do even if it looks
  helpful.
- **Files and edits** -- exact before/after snippets, not deltas or templates.
- **Quality gates** -- the `grep` and build/lint/test commands that must pass,
  written so the result is checkable rather than asserted.
- **Acceptance criteria** and a **commit message**.
- **Execution profile** -- recommended model class and reasoning depth, with a
  one-line rationale.

Two rules the shape does not state on its own:

- A before-snippet is taken from the pinned tree itself, never from a working
  copy or an upload that predates the pin. Pin the snippet to the hash, or
  have the agent re-read at that hash.
- An acceptance check is scoped to what was *removed*, not to a token. A
  criterion satisfiable only by touching retained code is a defect in the
  criterion -- surfaced by the agent, not satisfied by it.

Instruction files are ephemeral working papers, not tracked history. They move
one change from analysis to execution and are discarded once it lands; their
numbering carries no meaning and need not be contiguous. This is the opposite
of an ADR -- permanent, strictly monotonic, never renumbered. Nothing
downstream may depend on an instruction file's name or number.

Why the exactness: `AI-ORCHESTRATION.md#why-the-instruction-file-is-a-contract`.

## Authoring clauses every instruction obeys

1. **Acceptance observes the invariant.** When an instruction's goal states a
   tree-wide invariant, its acceptance is a tree-wide observation -- an
   analyzer run or an exhaustive structured search over every named surface --
   never a site list. A site list certifies the list; only the observation
   certifies the invariant.
2. **Sibling closure.** An instruction that types or otherwise migrates one
   field of a struct, one method of an interface, or one arm of a union
   enumerates every sibling of the same value class -- each either in scope or
   named as a deferral with its follow-up item id.
3. **Domain verification before retype.** Before an instruction narrows a
   value's type, the author verifies the full value domain at every write
   site, module-wide including `test/`: in-band sentinels and composite or
   namespaced values outside the target grammar block the retype until they
   are removed or the target design is widened by ratified decision.
4. **Deferrals carry owners.** Every deferral a gate can see -- a linter
   allowlist entry, a lossy `@go` redirect, an accepted-until-revisited note
   -- carries the roadmap item id that owns it. A deferral without an owner is
   a defect of the change introducing it.

## The execution profile is part of the contract

The analysis model records a recommendation in every instruction file: model
class, reasoning depth (none / brief / deep), and one line of why. The mapping
follows risk, not size. Mechanical work -- byte-exact application,
documentation, fixture churn behind count gates -- takes the smallest capable
model and no deep reasoning. Code changes verified by hermetic gates sit in the
middle. The strongest model with deep reasoning is reserved for acceptance that
includes live verification, debugging against a running system,
schema-and-codegen chains, or cross-cutting removals.

The profile is advisory to the operator, not a control: gates, before-snippets,
and stop-and-report apply identically under every profile. Why:
`AI-ORCHESTRATION.md#why-the-instruction-file-is-a-contract`.

## Decisions are ratified before instructions exist

Schema and structural decisions are resolved with the operator and recorded (as
`D`-numbered decisions) before any instruction that depends on them is
authored. An instruction never carries an unratified schema choice. This is the
invariant `AGENTS.md` and `CONTRIBUTING.md` state for the codebase, applied to
authoring: the decision is made by the operator, not discovered by the agent
mid-edit.

## Planning state lives in the roadmap item store, never in the chat

The analysis model tracks planning state through exactly one mechanism: the
checked-in `roadmap/` item store -- one markdown file per work item, managed
through the `roadmap-items` skill. There is no second place. The moment a
planning effort needs structure -- arcs, a status flip, a findings checklist, a
landed-vs-open ledger, a cross-arc execution order -- that structure is an item
(or a re-rank, or an `_order.md` edit) in the store, not prose in the
conversation. Planning that lives only in a transcript, a handover, or an
upload is not tracked.

The store holds only drift-invariant state: each item carries a `goal`, an
`acceptance_intent`, and `links`, never byte-exact snippets, file-and-edit
lists, or grep gates -- those are authored ephemerally at execution time and
discarded after they land. An item moves `proposed -> ratified -> done`;
`proposed` is all the analysis model writes, the flip is the operator's call
riding the ratifying commit, and a `done` item moves to `roadmap/completed/`.
Handovers and retrospectives may point at items by id but do not own the
tracking; when one enumerates open work under its own labels, the fix is to
write it into the store. ADRs and `D`-numbered decisions are the exception:
permanent, append-only, outside the store, never edited through it. Why:
`AI-ORCHESTRATION.md#planning-state-and-the-compaction-cost`.

## Code comments never leak the workflow's transient vocabulary

The planning store, instruction files, and chat transcript are *scaffolding*:
they produce a ratified change and fall away. A comment authored during this
loop must not reach back into the scaffolding -- no roadmap item id or arc
name, no instruction reference, no historical note, no chat-only category
("layer 1 / layer 2"). The discipline lives in the instruction's acceptance
criteria, not the executor's judgement. The operative rule and its discovery
grep are `docs/CODE-STYLE.md#self-contained-comments`, which `AGENTS.md` makes
an imperative for the agent; the one durable cross-reference a comment may
carry is an ADR (`docs/ADR-NNN-...`). Why:
`AI-ORCHESTRATION.md#transient-vocabulary-in-durable-code`.

## Anti-initiative is structural, not advisory

General-purpose models bias toward doing more than asked: migrating a config
silently, adding a helper before confirming the need, deleting a package
instead of wiring it. The countermeasure is structure, not a reminder: every
instruction carries an explicit out-of-scope list and an anti-initiative
clause, and substantive steps end in stop-and-report gates. The finest-grained
form appears in documentation work: annotate, do not rewrite, because ADR
numbering and ratified text are permanent.

Anti-initiative without an exit is lossy: the improvement the agent correctly
declined to make must land somewhere. It lands in the mandatory **Follow-up
candidates** section of the completion report (`AGENTS.md`), and the author
turns those candidates into roadmap items. Why:
`AI-ORCHESTRATION.md#the-follow-up-channel`.

## Cluster by risk, not by finding order

When a review produces many findings, group them by risk before sequencing.
Documentation-only patches bundle into a single PR -- they share one review
concern ("make the docs match the code"), and bundling saves a review cycle per
finding. Substantive changes -- schema, types, behavior -- stay separate and
cautious, one concern per PR.

## Removal is the default resolution

When a finding can be resolved by implementing dead surface or by removing it,
removal is the default. Dead schema fields, unreferenced config branches, and
documented-but-unwired capabilities are their own liability class: they invite
an author to set a field that does nothing. This is "code is liability" applied
to review findings.

## Review and retrospective practices

The neutral context-free checkpoint, the post-change-set retrospective, and the
snapshot-hygiene discipline they depend on are review-time practices, not
authoring-time ones, and live in `docs/AI-REVIEW-AND-RETROSPECTIVES.md`. One
snapshot-hygiene lesson is load-bearing at authoring time and is kept here:
scope a blast-radius search to the whole module, `test/` included -- integration
tests call production APIs exactly as production code does, so a removal arc
that greps only `internal/` and `cmd/` misses the integration-test callers.

## Inspect the whole file, never a ritual window

An existence or absence claim rests on a whole-file search (`grep -n` over the
whole file) or a full read, never on a slice. Both sides of the loop obey this:
a line window (`sed -n 'A,Bp'`, `head`, `tail`) is a guess about where the
answer lives, and a truncated slice looks exactly like a complete one.

A window is legitimate only after a search has located the target, to read
context the search cannot give cleanly -- prefer `grep -n -C3 PATTERN file`,
and reserve a bare `sed -n 'A,Bp'` for when a prior grep supplied line A. It is
the same whole-artifact discipline as the blast-radius rule above. Why:
`AI-ORCHESTRATION.md#the-ritual-window`.
