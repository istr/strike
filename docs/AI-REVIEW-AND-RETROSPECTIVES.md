# AI Review and Retrospective Practices

This document holds the review-time practices of strike's AI workflow: the
neutral context-free checkpoint, the post-change-set retrospective, and the
snapshot-hygiene discipline both depend on. They are extracted from
`AI-WORKFLOW.md` so that file stays the lean authoring contract; these are
consulted when a review or retrospective is commissioned, not at every
instruction-authoring anchor. Like the rest of the workflow, none of these is
aspirational -- each was adopted after a concrete failure made its absence
visible.

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

## See also

- `AI-WORKFLOW.md` -- the core human-AI loop and the authoring contract.
- `DESIGN-PRINCIPLES.md` -- the product axioms these reviews check against.
- `TYPE-SURVEY-RULEBOOK.md` -- the classification rules and boundary catalog a
  type-safety survey or its verification stage cites; a verdict without a
  citation is a defect of the audit.
