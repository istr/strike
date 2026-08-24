# roadmap-items: schema and rules reference

Read this when a field's meaning, an ordering question, or an edge case is
unclear. The SKILL.md covers the day-to-day; this file is the precise contract.

## Contents

- Item file shape
- Field reference
- The two ordering axes (rank vs _order.md)
- The dependency model (`depends_on`, `deps --check`, `order --topo`)
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
depends_on: [item-0031]
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
| `depends_on` | no | list | Hard blockers: item ids that must reach `done` before this item can start. One-way only -- see the dependency model. |
| `links` | no | list | Pointers to ADRs, specs, files. Pointers only, never copied content. **Non-blocking** -- a constraint belongs in `depends_on`. |
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

## The dependency model

`depends_on` is the third ordering input, and the only one that expresses a *hard*
constraint. `rank` is a preference within an arc, `_order.md` is a chosen
sequence; neither can say "0044 cannot start until 0031 lands". Without a stored
edge that fact lives only in the planner's head and has to be re-derived on every
reprioritization -- which is what this field removes.

Rules:

- **Semantics**: a blocker is satisfied only when its status is `done`. Ratified
  is not enough.
- **One direction.** The edge is stored on the dependent item. There is no
  `blocks:` field; dependents are always derived (`deps ID` shows them). A
  two-sided edge list in a hand-editable markdown store is a sync bug waiting to
  happen.
- **Drift-invariant** because item ids are stable and never reused, so an edge
  survives any amount of tree drift -- unlike a file path or a grep.
- **Cycles are refused at write time** by `update --add-dep`, not merely reported.
  A cycle is never a legitimate intermediate state. `deps --check` still detects
  one, because a hand-edit can introduce what the script would have refused.
- **Done items keep their edges.** They are the satisfied ends of chains, and
  dropping the edge on retirement would silently un-explain why the rest ran in
  the order it did.

`deps --check` is the whole payoff: it validates the edge set against the store
and the execution order in one pass, and exits non-zero, so it can run as a CI
check on the roadmap PR -- which is where this skill's hard guarantees are
supposed to live. It reports:

| Category | Meaning |
| --- | --- |
| `dangling` | `depends_on` names an id that does not exist. |
| `cycle` | A loop in the edge set, printed as the chain. |
| `order` | An item is scheduled before a blocker, or before a blocker that is unscheduled and not done. |
| `status-inversion` | A `ratified` item whose blocker is still `proposed`; or a `done` item whose blocker is not done. |

`order --topo` proposes a dependency-legal re-sort of `_order.md` as a diff and
**writes nothing**. The sort is stable -- keyed on each item's current position --
so an already-legal order comes back unchanged and only the items that must move
do. A from-scratch topological sort would shuffle unrelated items and discard the
human ordering judgement that is not expressible as an edge. Apply the proposal
with `reorder` (`--after-deps` places one item at its earliest legal slot); the
operator's ratifying commit stays the single handover.

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
