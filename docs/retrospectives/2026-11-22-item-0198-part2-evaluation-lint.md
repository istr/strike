# Retrospective: item-0198 part 2, the evaluation lint, and its three STOPs

Date: 2026-11-22. First anchor: `6d83ff6`. Landed in five commits:
`2e261a6` (roadmap), `11b2999` (ADR-049, `docs/CUE-WORKFLOW.md`), `4b9ca21`
(roadmap: scalar conjunct), `31b4170` (roadmap: measured stops), `97e33d8`
(lint).

## What happened

- The analysis model (Claude Opus 5.5) wrote the instructions and spike
  briefs; a coding agent executed them. A delegate-measure spike at
  `6d83ff6` measured the inventory with a prototype walk. The instruction
  dictated three commits; the first two landed.
- **STOP 1** (lint gate): the walk aborted at `trustlayers #Entry.layer`, a
  value of no kind. The instruction had added the abort on a value of no
  kind; it was never measured against the contract. The prototype had
  mapped every value of no kind to "scalar" without recording it.
- **Revision 1** (a scalar conjunct is a scalar; packages in sorted order):
  the roadmap commit landed, and **STOP 2** came at
  `crossval #AttestationVector.expected`. The analysis model's claim that
  the contract held only one value of no kind rested on a grep for index
  expressions and on reading two of the three comprehensions.
- **Spike 2** recorded every stop instead of raising it, and ran the
  measurement planned before part 4. Result: exactly two values of no
  kind; the inventory equals the deferral list; a value under
  `struct.MinFields(1)` has no kind but lists its fields; `Value.Default`
  reports a default for every list.
- **Revision 2** (a value of no kind that lists a field is entered as a
  struct): the roadmap commit landed, and **STOP 3** came in the test
  phase. The dictated test value `{} & struct.MinFields(1)` is a final
  error at compile time. The analysis model had named the risk, but not
  read the source that settles it.
- **Revision 3** (the abort test on `{...} & struct.MinFields(1)`) landed.

## Finding 1: a gate predicted from a condition nobody measured

The executor measured faithfully; the gap was in what the analysis model
asked it to measure. The prototype's classifier had a silent default branch
(no kind became "scalar", no event), so its inventory could not show where
a fail-closed abort would fire. The instruction then added that abort and
predicted `exit=0` from an inventory that was blind to it.

## Finding 2: a static claim stated wider than its evidence

"Only one value of no kind" came from two searches, neither of which
covered comprehensions in general. The executor's follow-up candidate,
"re-run the measurement with the abort turned into a report", was the
right fix and became spike 2.

## Finding 3: a premise derived by analogy that the source would have settled

`{} & struct.MinFields(1)` was assumed incomplete by analogy with the
measured `{[string]: ...}` case. Forty lines of `pkg/struct/struct.go` in
CUE v0.17.1 decide it: the error is incomplete only for an open struct or
one whose declared fields could still reach the count.

## What worked

- Each executor stopped at the first mismatch, changed nothing, and
  reported a precise diagnosis. There was no silent repair (contrast
  `2026-11-15-item-0016-discarded-instruction.md`).
- A delta on the dirty working tree, pinned by sha256, together with a
  named stash, kept every commit green and made each revision cheap. The
  state reconstructed from the instructions matched every sha256 the
  executor reported.
- The mechanical block-apply script removed transcription errors: no
  sha256 mismatch across four instructions.
- A test that checks its own premise (`TestWalkTakesScalarConjunct` in
  `tools/lintcue/contractvalues_test.go` at `97e33d8`) turns an unmeasured
  assumption into a visible failure, not a passing test that proves
  nothing.

## Lessons

1. **A fail-closed condition is measured before it gates.** Before an
   instruction gates on a condition that can abort a run, a measuring
   program records every instance of it in the real tree instead of
   stopping at the first.
2. **A measuring program has no silent default branch.** Every class it
   maps away is recorded as an event, so the report shows what was not
   examined.
3. **A derived premise is checked against the source before it is
   dictated.** A premise inferred by analogy is read against the source of
   the thing it concerns. Where it stays unmeasured, the dictated test
   checks it itself, and the instruction says so.
4. **A static claim names its search.** A claim of the form "only one" or
   "none" states the search behind it and that search's limits; if the
   claim gates, it is measured.

## Adopted

Ratified by the operator on 2026-11-22 and landed in the commit that adds
this retrospective: rules 1, 3 and 4 as one paragraph of authoring clause 5
of `AI-WORKFLOW.md` ("gate values are measured, not derived"), which they
extend from counts to the conditions and premises a gate depends on; rule
2 as one sentence of its "Delegate the measurement" path. Both stay terse
and carry no backstory: at `97e33d8`, `AI-WORKFLOW.md` already holds 17502
characters, above the 16000-character read-at-once limit that item-0145 is
to gate.
