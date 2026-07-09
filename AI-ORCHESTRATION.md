# AI Orchestration: The Orchestrate-Only Development Model

strike is written under an orchestrate-only model. One human operator ratifies
every decision and writes no production code. A general-purpose language model
reads the pinned tree, produces architectural analysis, and authors byte-exact
instruction files. A separate coding agent applies those instructions, runs the
gates, and commits. Nothing else touches the repository.

This document explains that model, records what each of its rules cost to
learn, and points at the evidence. It is the concept paper, a peer of
`DESIGN-PRINCIPLES.md`, which states the axioms of the *product*. The rules
themselves live where they are obeyed: `AGENTS.md` holds the executor
imperatives, `AI-WORKFLOW.md` holds the loop imperatives and the placement rule
that decides which file a new rule enters. Nothing here is a rule. If a
sentence in this file reads like an instruction, the instruction is stated
elsewhere and this file is explaining it.

The empirical record is `docs/retrospectives/`. Every imperative in the two
rule files traces back to a dated failure or measurement written down there;
this document is the synthesis, not the source.

## The orchestrate-only model

Three roles, one direction of authority. Analysis flows up to the operator for
ratification; instructions flow down to the agent for execution. Neither model
decides scope, and the two models never talk to each other -- the ratifying
commit is the only channel between them.

The strict separation is not an efficiency measure. It exists because the two
failure modes of a general-purpose model are opposite in character, and each
role's constraints suppress one of them:

- An **author** with a build toolchain starts running things, then reports the
  results of a run it half-understood as if they were reasoning. Removing the
  toolchain forces the author to state what it believes and why, in a form the
  executor's gates can falsify.
- An **executor** with design latitude starts improving. It migrates a config
  it was not asked to migrate, adds a helper before confirming the need,
  deletes a package it should have wired in. Removing the latitude -- a
  byte-exact before-snippet, an out-of-scope list, a stop-and-report gate --
  turns "the tree drifted" from a silent corruption into a caught error.

The operator is the only role that can hold both, and holds neither: the
operator ratifies and does not write.

## Role economics: state access and cost, not capability

The two model roles are frequently the same model class. The axis that
separates them is not how capable they are; it is **what state they can reach
and what a mistake costs there**.

The author reaches a pinned, read-only tree and its own context. Its mistakes
are cheap and legible: a wrong before-snippet fails to match and the run stops.
Its expensive failure is invisible -- a confident claim about something it
could not observe. So the author's discipline is epistemic: separate the static
question (readable from source) from the dynamic one (needs the toolchain), and
never present a guess about the second as a measurement.

The executor reaches a writable tree, a network, a container engine, and the
commit. Its mistakes are expensive and, unchecked, silent. So the executor's
discipline is procedural: apply exactly what was written, run the full gate,
and report -- including what it noticed and declined to do.

Capability parity across the two roles is what makes the split informative
rather than merely bureaucratic. When the same model class produces different
results in the two harnesses, the difference is attributable to state access
and cost, not to intelligence.

## Why the instruction file is a contract

Work reaches the coding agent as a numbered instruction file with exact
before/after snippets, not as a conversational request. The agent handles
"replace this exact text with that exact text" far more reliably than "make
this kind of change." Pinning the before-snippets to a named hash turns the
product's determinism discipline inward onto its own process: a snippet that
does not match triggers a stop-and-report instead of an improvised edit.

Two corollaries were earned rather than designed.

First, a before-snippet must come from the pinned tree, not from a working copy
or an upload that predates the pin. Unpushed reformatting made an upload differ
in whitespace alone; the byte-exact snippet then failed to match for a reason
unrelated to drift. Noise of that kind trains the agent to read stop-and-report
as a false alarm, which is precisely the reflex the mechanism depends on not
having.

Second, an acceptance check must be scoped to what was *removed*, not to a
token. When a deleted path and a retained path share a term, a blanket "this
grep returns nothing" cannot pass without cutting code meant to stay. A
criterion satisfiable only by damaging retained code is a defect in the
criterion, and the agent is instructed to say so rather than satisfy it.

Instruction files are ephemeral working papers. They move one change from
analysis to execution and are discarded once it lands; their numbering carries
no meaning. This is the exact opposite of an ADR -- permanent, strictly
monotonic, never renumbered -- and the contrast is deliberate: the durable
record is the decision, never the mechanics of applying it.

**The execution profile** rides in the same file: model class, reasoning depth,
one line of why, chosen by risk rather than size. It is advisory to the
operator's launch choice and never modifies the contract. Its value is the
inverse of what it looks like: when an under-profiled session grinds against
its gates, the mismatch is visible and named at the moment it happens, instead
of being diagnosed afterward from a wreck.

## Grounding: predict-and-gate, or delegate the measurement

The author has no build, test, or codegen toolchain. That absence is a design
choice, not a limitation to be routed around: narrowing what the author can do
narrows what an over-eager author can quietly get wrong.

It also forces every load-bearing dynamic question onto one of two named paths.
When a careful reader can determine the outcome from the pinned source, the
instruction **predicts and gates**: it states the expected outcome and makes
the agent's own build or test the proof, so a deviation stops the run instead
of shipping. When the outcome is generator-internal or otherwise unreadable,
the measurement is **delegated**: the agent runs the operation in a throwaway
worktree, reports the result, commits nothing, and the byte-exact steps that
depend on the value are authored only afterward.

The discriminator is whether the byte-exact *content* depends on the measured
value, or only the *gating* does. Confidence is explicitly not the test. A
guess dressed as a prediction still ships unverified, and an instruction
resting on a measurement its author could not take is either a fabrication or
an unverified guess. Both are worse than a named hand-off.

## The follow-up channel

Anti-initiative is the executor's cardinal discipline, and for a long time it
had no exit. The instruction said: report a correct-but-out-of-scope
improvement as a follow-up candidate, never implement it in passing. The
executor complied. The candidates went into a completion report, the report
went into a transcript, and the transcript was compacted.

The residue was measurable. A migration wave typed one field of an option
struct and left its siblings as bare strings, exactly as scoped -- and nothing
in the system remembered that the siblings existed. This is mechanism M2 below.

The fix is structural on both ends. The executor's completion report now ends
with two mandatory sections, **Observations** and **Follow-up candidates**, and
a missing section is a gate failure. The author's side answers with sibling
closure: an instruction that migrates one field of a struct enumerates every
sibling of the same value class, each either in scope or named as a deferral
carrying the roadmap item id that owns it. A deferral a gate can see but no
item owns is a defect of the change that introduced it.

## The blame reflex

A failing gate provokes a trained reflex: ask whether this change was at fault,
and stop at the first plausible external cause. The environment. A prior
commit. An unexpected file. Each of those is a verdict about responsibility,
and none of them is a diagnosis. The defect stays in the tree.

The countermeasure states that blame is irrelevant and worth zero reasoning,
names the three forbidden stopping points explicitly, and fixes the diagnostic
order: re-read the spec, then the existing code, then your own change. The
order matters because it grounds the diagnosis in declared intent and the
existing contract before it reaches the edit that is easiest to suspect.

The rule that no gate may be shrunk to make it pass -- no package selector, no
`-run` filter, no `t.Skip` -- belongs to the same reflex. A gate that is green
because its scope was cut has been disabled, not passed, and the disabling is
almost always reported as a success.

## The ritual window

Both sides of the loop shared one failure: inspecting a file through an
arbitrary line window -- `sed -n 'A,Bp'`, `head`, `tail` -- as the way to find
out what the file contains, rather than to read a region already located.

The window is a guess about where the answer lives, committed before the
answer's location is known. When the guess is wrong, the output does not
announce its incompleteness: a truncated slice of a target list looks exactly
like a complete list, so a wrong window becomes a confident "it is not there."
A line window is a declaration about where to observe, and a negation drawn
from a declaration is the move the product's observation-defeats-declaration
principle forbids, here turned inward on the tooling.

The habit is borrowed. The shell examples models learned from window files
because scrolling a terminal is tedious -- an ergonomic reason with nothing to
do with reading a file into context. On a small file the window saves no
meaningful context and buys an unbounded, invisible correctness risk, so the
feedback that would retire it rarely arrives.

The failure that fixed this as a rule: a session concluded that a harness
Makefile target did not exist, from a window that ended a few lines above its
definition. A whole-file grep corrected it -- the target was named in the
`.PHONY` line the window had cut off.

## Planning state and the compaction cost

Planning that lives only in a transcript, a handover, or an upload is not
tracked. It is one compaction away from loss, and the cost was paid once: a
compaction blurred an iterative arc sequence, and the next handover had to
reconstruct landed-versus-open state from a transcript.

Planning state therefore lives in exactly one place, the checked-in `roadmap/`
item store: one markdown file per item, diffable, reviewable in a pull request,
queryable from the tree. The store holds only drift-invariant state -- a goal,
an acceptance intent, links. Byte-exact snippets and grep gates are deliberately
excluded, because a stored item carrying a stale snippet is worse than no item:
it trains a false-alarm stop-and-report the first time the tree moves.

Retrospectives and handovers may summarize and point at items by id, but they
do not own the tracking. When one of them starts enumerating open work under
its own labels, that is the signal of a missing or stale item.

## Transient vocabulary in durable code

The planning store, the instruction files, and the chat transcript are
scaffolding: they produce a ratified change and fall away. The code that lands
is durable and has to stand alone.

So a comment authored inside this loop must not reach back into the
scaffolding: no roadmap item id, no arc name, no instruction reference, no
historical narrative, no chat-only category. The trap is structural rather than
careless -- the author who has the context is exactly the one who cannot tell
that the comment is unmoored. The discipline therefore lives in the
instruction's acceptance criteria, where a grep can enforce it, and not in the
executor's judgement. The one durable cross-reference a comment may carry is an
ADR.

## The mechanism taxonomy

Defects are not uniform debt. Each migration wave's execution mechanism leaves
a characteristic residue, and the residue is more informative than the site
count. Every defect gets a mechanism label; the primary output of a
retrospective is the mechanism fix -- a gate, a channel, an owner -- with the
code fix secondary.

- **M1 gate-narrower-than-goal.** The item's goal states a tree-wide
  invariant; the standing gate observes one syntactic position.
- **M2 anti-initiative without a follow-up channel.** Byte-exact scope
  discipline works as designed and leaves half-migrated seams, because the
  mandated follow-up candidates never became items.
- **M3 deferral without an owner.** Allowlist entries, lossy annotations, and
  accepted-until-revisited notes with no item id attached.
- **M4 fresh code regresses where no gate observes.** New contract fields whose
  doc comments state a typed grammar while the field declares a bare string.
- **M5 toolchain loss mislabeled as debt.** A generator limitation is worked
  around at the call sites instead of at the annotation, and the workaround is
  filed as debt. The fix is a visibility rule, not caller-side churn.
- **M6 never-scoped subsystem.** Packages outside every migration arc's file
  list simply keep their pre-migration shape.

M1 is answered by the invariant-observation clause, M2 by the follow-up channel
and sibling closure, M3 by the deferral-owner clause, M5 by domain verification
before retype. M4 and M6 are answered by standing gates rather than by
authoring rules.

## The diff is the product

The taxonomy above came out of running the same audit twice on the same pinned
tree, deliberately varying the harness while holding the model class constant:
once through the analysis lane (read-only, single context, a self-built
parse-only scan) and once through the executor lane (full toolchain, a
type-checked extractor, a parallel trace sweep, an adversarial verification
stage).

The overlap was the boring part. Both lanes found every high-fan-out defect
family. The information was in the single-side and disputed sets: findings one
harness could see and the other structurally could not, and findings the two
lanes disagreed about. Three of them changed remediation plans, which is the
concrete return on paying for the audit twice.

Two second-order results are worth more than the findings. Both lanes
independently invented the same tool -- an abstract-syntax-tree fact extractor
-- differing only in whether a type checker was available. A tool that both
lanes invent wants to exist, so it is being reified as a standing gate rather
than rebuilt ad hoc by whichever lane runs the next audit. And the difference
between the two runs, treated as the product, is what produced the mechanism
labels; neither report contained them.

Full dual runs are expensive and are reserved for tree-wide invariants and
high-stakes analyses. The default is the deterministic extractor plus one
judgment pass; the multi-agent sweep runs per release or per migration wave.

## Evidence base

- `docs/retrospectives/` -- dated retrospectives, one per change set, audit, or
  incident. Every rule above cites its origin there.
- `docs/AI-REVIEW-AND-RETROSPECTIVES.md` -- the review-time practices that
  produce those documents.
- `AI-WORKFLOW.md` -- the loop imperatives, and the placement rule that decides
  whether a new lesson becomes a rule there, a rule in `AGENTS.md`, or a
  section here.
- `AGENTS.md` -- the executor imperatives, including the completion report.
- `roadmap/` -- the item store; open work identified by any retrospective is
  written there and referenced by id.
