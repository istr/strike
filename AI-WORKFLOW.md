# Working With AI: Collaboration Practices

strike is built in an AI-heavy workflow: an operator works with a
general-purpose language model to do architectural analysis and author
instruction files; a separate coding agent executes those instructions against
the codebase. This document records the collaboration practices that have
proven effective and the reasoning behind each. It is distinct from its
neighbors -- `DESIGN-PRINCIPLES.md` states the axioms of the *product*,
`AGENTS.md` gives imperative rules to the *coding agent*, `CONTRIBUTING.md`
defines review criteria for *changes*, and this file describes how the
*human-AI loop itself* is run. None of the practices is aspirational; each was
adopted after a concrete failure made its absence visible.

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
the pinned tree, text search, and the planning script -- enough to read any
file at a named hash, confirm a string's shape and count, and move a roadmap
item. It does not have the build, test, or codegen toolchain. That absence is a
design choice: the author of instructions stays in the read-reason-author lane,
and build-and-run belongs to the coding agent alone. Narrowing what the author
can do narrows what an over-eager author can quietly get wrong.

This splits grounding into two kinds. A *static* question is settled by reading
the pinned source: whether a before-snippet appears exactly once, where a
base/wire boundary falls, whether a generated artifact is gitignored, what a
function does to an input. The analysis model answers these itself -- they are
the substance of grounding. A *dynamic* question needs the toolchain to run:
whether a generator reorders output after a file move, whether a golden is
byte-identical after a rename, whether `make check` passes. The analysis model
does not run these, and does not present a guess about one as if it had
measured it.

A load-bearing dynamic question is resolved one of two ways, chosen by a single
test: can a careful reader determine the outcome from the pinned source alone?
When yes, the instruction **predicts and gates** -- it states the expected
outcome and makes the agent's own build/test gate the proof, so a deviation
stops the run instead of shipping. When no -- the outcome is generator-internal
or otherwise unreadable, and load-bearing -- the measurement is **delegated**:
the agent runs the operation in a throwaway worktree and reports the result,
and the byte-exact steps that depend on it are authored only afterward (the
measurement is scratch, never committed). The discriminator is whether the
byte-exact *content* depends on the measured value (delegate) or only the
*gating* does (predict). Confidence is not the test: a guess dressed as a
prediction still ships unverified, and an instruction resting on a measurement
its author could not take is either a fabrication or an unverified guess --
both worse than a named hand-off.

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
  The agent handles "replace this exact text with that exact text" far more
  reliably than "make this kind of change".
- **Quality gates** -- the `grep` and build/lint/test commands that must pass,
  written so the result is checkable rather than asserted.
- **Acceptance criteria** and a **commit message**.
- **Execution profile** -- recommended model class and reasoning depth, with a
  one-line rationale.

The exactness is the point: a before-snippet that does not match triggers a
stop-and-report instead of an improvised edit, converting "the tree drifted"
from a silent corruption into a caught error. Pinning before-snippets to a
named hash turns the project's determinism discipline inward onto its own
process.

Two corollaries earned in practice. First, a before-snippet must be taken from
the pinned tree itself, not a working copy or an upload that predates the pin:
unpushed reformatting can make an upload differ in whitespace alone, and a
byte-exact snippet then fails to match for a reason unrelated to drift -- noise
that trains the agent to treat stop-and-report as a false alarm. Pin the
snippet to the hash, or have the agent re-read at that hash. Second, an
acceptance check must be scoped to what was *removed*, not to a token: when a
deleted path and a retained path share a term, a blanket "this grep returns
nothing" cannot pass without cutting code meant to stay. Write the criterion
against the deleted artifact (a removed type, a deleted file), and treat one
satisfiable only by touching retained code as a defect in the criterion --
surfaced by the agent, not satisfied by it.

Instruction files are ephemeral working papers, not tracked history. They move
one change from analysis to execution and are discarded once it lands; their
numbering carries no meaning and need not be contiguous. This is the opposite
of an ADR -- permanent, strictly monotonic, never renumbered. Nothing
downstream may depend on an instruction file's name or number.

## The execution profile is part of the contract

The analysis model, which knows an instruction's risk class best at the moment
of writing, records a recommendation in the file: model class, reasoning depth
(none / brief / deep), and one line of why. The mapping follows risk, not size.
Mechanical work -- byte-exact application, documentation, fixture churn behind
count gates -- needs the smallest capable model and no deep reasoning; the
gates carry the safety, and a stronger model adds cost and initiative surface,
not quality. Code changes verified by hermetic gates sit in the middle. The
strongest model with deep reasoning is reserved for instructions whose
acceptance includes live verification, debugging against a running system,
schema-and-codegen chains, or cross-cutting removals.

The profile is advisory to the operator, not a control. Gates, before-snippets,
and stop-and-report apply identically under every profile; a stronger model is
never a license to loosen them, a weaker one never an excuse for a gate to
fail. Its value is the inverse: when an under-profiled session grinds against
its gates, the mismatch is visible and named instead of diagnosed after the
fact.

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
through the `roadmap-items` skill. There is no second place; the prose
`docs/ROADMAP-*.md` files this once named have been retired. The moment a
planning effort needs structure -- arcs, a status flip, a findings checklist, a
landed-vs-open ledger, a cross-arc execution order -- that structure is an item
(or a re-rank, or an `_order.md` edit) in the store, not prose in the
conversation. Planning that lives only in a transcript, a handover, or an
upload is not tracked; it is one compaction away from loss -- a cost paid once,
when a compaction blurred an iterative arc sequence and a handover had to
reconstruct landed-vs-open state from a transcript.

The store holds only drift-invariant state: each item carries a `goal`, an
`acceptance_intent`, and `links`, never byte-exact snippets, file-and-edit
lists, or grep gates -- those are authored ephemerally at execution time and
discarded after they land. An item moves `proposed -> ratified -> done`;
`proposed` is all the analysis model writes, the flip is the operator's call
riding the ratifying commit, and a `done` item moves to `roadmap/completed/`.
The query path is the point: "what is open in arc X by rank", "what runs next",
"landed vs open" are answered against the tree through the skill, not
reconstructed from prose. Handovers and retrospectives may summarize and point
at items by id but do not own the tracking; when one enumerates open work under
its own labels, that signals a missing or stale item, and the fix is to write
it into the store. ADRs and `D`-numbered decisions are the exception:
permanent, append-only, outside the store, never edited through it.

## Code comments never leak the workflow's transient vocabulary

The planning store, instruction files, and chat transcript are *scaffolding*:
they produce a ratified change and fall away. The code that lands is durable
and must stand alone, so a comment authored during this loop must not reach
back into the scaffolding -- no roadmap item id or arc name, no instruction
reference, no historical note, no chat-only category ("layer 1 / layer 2").
The trap is structural: the author who has the context is exactly the one who
cannot tell the comment is unmoored, so the discipline lives in the
instruction's acceptance criteria, not the executor's judgement. The operative
rule and its discovery grep are `docs/CODE-STYLE.md#self-contained-comments`,
which `AGENTS.md` makes an imperative for the agent; the one durable
cross-reference a comment may carry is an ADR (`docs/ADR-NNN-...`).

## Anti-initiative is structural, not advisory

General-purpose models bias toward doing more than asked: migrating a config
silently, adding a helper before confirming the need, deleting a package
instead of wiring it. The countermeasure is structure, not a reminder: every
instruction carries an explicit out-of-scope list and an anti-initiative
clause, and substantive steps end in stop-and-report gates. The finest-grained
form appears in documentation work: annotate, do not rewrite, because ADR
numbering and ratified text are permanent.

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

Both sides of the loop share a failure: inspecting a file through an arbitrary
line window -- `sed -n 'A,Bp'`, `head`, `tail` -- as the way to find out what
the file contains, rather than to read a region already located. The window is
a guess about where the answer lives, committed before the answer's location is
known, and when the guess is wrong the output does not announce its
incompleteness: a truncated slice of a target list looks exactly like a
complete list, so a wrong window becomes a confident "it is not there". A line
window is a declaration about where to observe, and a negation drawn from a
declaration is the move the product's "observation defeats declaration"
principle forbids -- here turned inward on the tooling.

The habit is a borrowed idiom: the shell examples models learned from window
files because scrolling a terminal is tedious -- an ergonomic reason with
nothing to do with reading a file into context. On a small file it saves no
meaningful context and buys an unbounded, invisible correctness risk, so the
feedback that would retire it rarely arrives. The failure that fixed this as a
rule: a session concluded a harness Makefile target did not exist from a window
that ended a few lines above its definition, and was corrected by a whole-file
grep -- the target was named in the `.PHONY` line the window cut off.

The rule, imperative for the agent in `AGENTS.md` and practice here: an
existence or absence claim rests on a whole-file search (`grep -n` over the
whole file) or a full read, never a slice. A window is legitimate only after a
search has located the target, to read context the search cannot give cleanly
-- prefer `grep -n -C3 PATTERN file`, where the match anchors the window, and
reserve a bare `sed -n 'A,Bp'` for when a prior grep supplied line A. It is the
same whole-artifact discipline as the blast-radius rule above: scope the
observation to the whole artifact, because what you seek is as likely to sit
outside your window as inside.
