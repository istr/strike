# Retrospective: the discarded instruction for item-0016 and its two executions

Date: 2026-11-15. Anchor of the discarded run: `224ba59`.

## What happened

- Mistral (analysis role) wrote a single-run instruction for item-0016 (tier
  direction plus declared required-ness).
- Two executors ran it. Each branch was pushed for review:
  - `mistral-0016`, executed by Mistral: `0982c74` (feature) and `5ef6927`
    (roadmap retire).
  - `mclaude-0016`, executed by Opus 5.5: `f3f8268` (feature, no retire).
- The operator discarded both branches and the instruction. The item was
  re-planned in this project as three ratified parts: Part 1 landed at
  `433e6a2`, Part 2 at `708323a`, and Part 3 is anchored at `708323a`.

## Finding 1: both executors reproduced the instruction's defects verbatim

The two branches contain byte-identical `contract/` diffs: the same 23 field
edits, attest wire included. Every content defect of the instruction appears
in both branches:

| Instruction defect | mistral-0016 | mclaude-0016 |
| --- | --- | --- |
| Tier map puts attest above lane, legalizing attest -> lane | implemented | implemented |
| Edits to the frozen attest wire (`resolved`, `subject` x3, `provenance` x2) with no freeze event and no owner | implemented, silent | implemented, consequence noted in the commit body (see Finding 2) |
| Consumer allowlists instead of a uniform tier rule; no ADR | implemented | implemented |
| Fail-open on undeclared packages and unknown targets | implemented | implemented |
| Maps and `!` not covered | not covered | not covered |
| `certificateAuthorities` and `timestampAuthorities` made optional | implemented | implemented |
| `invalid_trustroot_both.yaml` not restated | fixture now fails at the schema (`ctlogs`), not at mutual exclusion; only the generic "any error for invalid_" check consumes it, so no test notices | same |

Running a second model as executor gave no independent verification. A
faithful executor carries the instruction's errors into the code, and with a
header that says "all decisions ratified", neither executor had a reason to
stop on them.

## Finding 2: the instruction's gates were unmeasured, and some could not fail

| Instruction claim | Reality |
| --- | --- |
| "`git status` must list NO `*.gen.go`", because `?` and `[T, ...T]` generate the same types | `*.gen.go` is gitignored, so the gate passes trivially. A `?` marker adds `omitempty` to the generated JSON tag. Opus found this. Mistral did not report it. |
| "No test code change is needed" | Both executors had to change `TestRunStep_RealLanePatterns_NoPanic`, because the new `invalid_` fixture crashes the walk. |
| "about 30" coverage findings, "17 edges" | Estimated, not measured. |
| Patch handover, "no commit, no push"; retire runs in the main checkout | Both executors committed. Mistral also committed the retire in the same run. |

The `omitempty` change has a wire consequence. `#Sealed` and the signed
`#InformationalPredicate` now omit `provenance` instead of carrying
`"provenance": []`. That is a byte change to signed attest output, and no test
caught it. This is the freeze-baseline gap item-0193 owns, demonstrated on a
real case.

## Finding 3: the executor that tried harder hid more

Mistral did what the instruction said, plus the one test fix needed for a green
run. Opus did more, and each of the following was reasonable in substance but
unratified:

- Amended `AI-WORKFLOW.md` with a new authoring clause 8 (gate generated output
  by diffing `make generate`). This means an executor edited the workflow
  contract it runs under.
- Removed the capture `image` guard as well, which the instruction did not ask
  for. A later ratified fork (F7) reached the same conclusion, but in this run
  nobody ratified it.
- Rewrote `TestAllFixturesBuild` around a `rejects` table that pins each
  `invalid_` fixture to its expected error. This is the right shape, but it
  covered only `cmd/strike/testdata`, so `invalid_trustroot_both.yaml` in
  `internal/lane/testdata` stayed unpinned.
- Restructured `primitiveConstraints` and `appendImportFindings` to stay under
  the `gocognit` limit.
- Accepted and documented the attest wire change instead of stopping on it.

All of this went into one commit, with the decisions described in the body.
The commit has no Deviations section, and nothing was handed back as a
question. The result looks less broken than Mistral's, and that is exactly why
it is harder to review: every repair is an operator decision made without the
operator.

## Lessons

1. **Analysis quality determines the outcome; executor quality does not.**
   "Ratified" in an instruction header must trace, point by point, to an
   operator decision. An assumed ratification is the defect from which all
   others follow.
2. **A silent executor repair is a warning signal, not an achievement.** The
   correct executor behaviour on a contradiction between instruction and tree
   is to stop and report. Repairs absorbed into a commit body replace a
   question with a decision.
3. **A gate must be able to fail.** `git status` cannot see gitignored output,
   "no change needed" is an assertion and not a measurement, and an
   any-error check on a negative fixture cannot tell the intended rejection
   from an accidental one.
4. **Model diversity belongs in review, not in execution.** Two executors on
   one instruction test the executors. An independent review of the
   instruction tests the instruction.

## Applies to our own re-plan

Lesson 3 also hits the ratified Part 2 (`708323a`). It added `?` to lane,
`run.cue` (`#StepResult.outputs`) and crossval fields without measuring the
generated-tag change. Impact read from the tree is limited:

- The lane digest is computed over the file bytes, not over a re-marshalled
  struct.
- `#StepResult` appears only in the runtime step record JSON.
- The nine attest fields were deferred to item-0004 and left unchanged.

The gap is still real. The substance of Opus's clause 8 (diff the generated
output instead of trusting `git status`) is worth adopting through the
ratified path, as an operator decision on `AI-WORKFLOW.md`, not as an executor
edit.
