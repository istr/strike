# roadmap-items: schema and rules reference

Read this when a field's meaning, an ordering question, or an edge case is
unclear. The SKILL.md covers the day-to-day; this file is the precise contract.

## Contents

- Item file shape
- Field reference
- The two ordering axes (rank vs _order.md)
- Rank mechanics and rescale
- `_order.md` format
- Status model and the ratification gate
- Why byte-exact contracts are excluded

## Item file shape

One file per item at `roadmap/<id>.md` (active) or `roadmap/completed/<id>.md`
(done). The file is YAML-subset frontmatter between `---` fences, then a short
markdown body. The script serializes fields in a fixed canonical order so diffs
stay small and reviewable; do not hand-reorder fields.

```yaml
---
id: item-0042
status: proposed
arcs: [output-model, image-from-step]
rank: "0030"
title: "Add OutputRef disjunction to deploy.artifacts.from"
goal: "deploy.artifacts.from is a step|step+output disjunction"
acceptance_intent: "CUE validates both ref shapes; goldens regenerate"
links: [ADR-046]
execution_profile: { class: smallest, reasoning: none }
---
Short, drift-invariant notes: rationale, open questions. No byte-exact snippets.
```

## Field reference

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `id` | yes | `item-NNNN` | Stable identity, referenceable in commit messages. Never reused, even after archival. Allocated as max existing id + 1. |
| `status` | yes | enum | `proposed`, `ratified`, or `done`. See the status model. |
| `arcs` | yes | list | One or more arc names. Arcs are **query tags**, not the execution sequencer. An item may belong to several arcs. |
| `rank` | yes | zero-padded string | Orders items **within** an arc. Numeric-sparse: `"0010"`, `"0020"`, ... |
| `title` | yes | one line | Human label. |
| `goal` | yes | one line | The drift-invariant end state. What "done" means in one sentence. |
| `acceptance_intent` | yes | string | The **intent** of acceptance -- what must become true -- not byte-exact greps or file lists. Drift-invariant. |
| `links` | no | list | Pointers to ADRs, specs, files. Pointers only, never copied content. |
| `execution_profile` | no | inline map | Advisory `{ class, reasoning }` hint for how to run the eventual instruction. Drift-invariant because it tracks the nature of the change (mechanical vs design-heavy), not byte details. Never gates anything. |

The body holds short drift-invariant prose only. Once an item is `done`, the
executor appends a `## Final summary` section recording what landed (and ideally
the commit), then the file moves to `completed/`.

## The two ordering axes

These are intentionally separate; conflating them is the most likely modeling
mistake.

- **`rank`** is intra-arc. It answers "what is open in arc X, by rank". It is a
  per-item scalar used as the sort key whenever you filter to one arc.
- **`_order.md`** is the single cross-arc execution order. It answers "what runs
  next". It is a flat, ordered list of item IDs.

Why a global list rather than sequencing arcs: items can carry multiple arcs, so
"sequence the arcs" would give a multi-arc item several positions and need a
tiebreak. A global item list sidesteps that, makes "what's next" unambiguous, and
expresses an arc-crossing move (an item leaving one arc for another) as a plain
`restructure` plus a `reorder`, with no special case.

Consequence to keep in mind: an item can rank high within its arc yet sit late in
global execution order. That is expected, not a bug. `rank` is for planning
visibility inside an arc; `_order.md` is for execution sequence across everything.

## Rank mechanics and rescale

Ranks are zero-padded integers stored as strings (`"0030"`), so lexical and
numeric sort agree. Spacing is sparse (step of 10 by default) so inserts are
midpoint operations that leave neighbours untouched:

- `rank ID --to 0035` sets an explicit rank.
- `rank ID --between A B` computes `(rank(A) + rank(B)) // 2`.

If two neighbours are adjacent (e.g. `0034` and `0035`) there is no integer gap.
The command **stops** and tells you to re-space the arc first:

```
rescale <arc> [--step 10]
```

`rescale` renumbers every item in one arc, in current rank order, to `0010`,
`0020`, `0030`, ... It is explicit and operator-invoked -- a visible, bounded
renumber, never a silent cascade triggered by an insert. After rescaling, retry
the insert.

This sparse-integer scheme was chosen over LexoRank deliberately: at this scale
(one operator, dozens of items) LexoRank's midpoint-string machinery buys
collision-proof inserts you will almost never need, at the cost of more code and
less readable diffs. Zero-padding leaves a clean upgrade path to LexoRank if gaps
are ever genuinely exhausted.

## `_order.md` format

A header comment plus one `- <item-id>` per line. Order is line order. Only
execution-relevant items need to appear; an item not listed is simply
unscheduled. IDs only -- titles live in the item files, so there is one source of
truth for a title.

```
# Execution order (global, cross-arc)

Items run top to bottom; order is line order. Each line is `- <item-id>`.
...

- item-0017
- item-0042
```

`reorder` maintains this file: `--before`/`--after` an anchor, `--to-position N`,
or `--remove` to unschedule. `done` drops the id automatically.

## Status model and the ratification gate

```
proposed  --(operator ratifying commit/merge)-->  ratified  --(executor)-->  done
```

- Analysis writes only `proposed`.
- `proposed -> ratified` is operator-only. The script will flip the field, but the
  **real** gate is the ratifying commit/merge enforced by branch protection and
  review. The flag-flip is bookkeeping riding along with that merge. The script
  refuses backward or skipping transitions unless `--force` is passed for a
  correction.
- `ratified -> done` is the executor's: it writes the final summary, moves the
  file to `completed/`, drops the id from `_order.md`, and commits with the item
  id in the message.

There is no auto-ratify, by decision: ratification is a scope checkpoint, and even
a mechanical change can be mis-scoped. Keep the human checkpoint; make the merge
cheap (a one-line approve), not skippable.

`list` shows the **active set** (proposed + ratified) by default, since done items
move to `completed/` specifically to keep the working list small. Pass `--status
done` to see only archived items, or `--all` to include them alongside the active
set.

## Why byte-exact contracts are excluded

The durable store holds only what stays true as the working tree drifts. Byte-
exact before/after snippets, exact file-and-edit lists, and exact grep gates are
pinned to a specific tree hash. Storing them means that the moment the tree moves,
the stored item is wrong -- and a confidently-wrong stored snippet trains exactly
the false-alarm stop-and-report behaviour the workflow is trying to avoid. So the
full byte-exact instruction is authored ephemerally at execution time against the
then-current pin, used, and discarded. The item keeps only the drift-invariant
intent (`goal`, `acceptance_intent`, `links`).
