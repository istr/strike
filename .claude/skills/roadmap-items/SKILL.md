---
name: roadmap-items
description: >-
  Manage an item-based roadmap/backlog stored as markdown files in the git repo
  (one file per work item, planning-state frontmatter only). Use this skill
  whenever the user wants to create, query, re-status, reprioritize, restructure,
  archive, or read the cross-arc execution order of planning items, roadmap arcs,
  or "landed vs open" state -- even if they only say "update the roadmap", "what's
  still open in arc X by rank", "what's next to execute", "park this for later", or
  describe planning state in prose. Prefer this over hand-editing prose roadmap
  files: hand edits drift and break single-source. Stores planning state only,
  never byte-exact instruction contracts. Never touches ADRs or D-numbered
  decisions. Reach for it on any roadmap, backlog, arc, work-item, or
  what-runs-next question. The runnable script lives in this skill's own
  scripts/ directory, not at repo-root scripts/; see Commands for the exact
  per-environment invocation.
---

# roadmap-items

A queryable, item-based roadmap store that lives as plain markdown in the git
repo. One file per work item, planning-state only, diffable, reviewable in a PR.
It replaces prose roadmap documents so there is exactly one place planning state
lives.

## Why this exists

Moving a work item between roadmaps by hand -- re-typing it, re-scoping greps,
keeping a prose execution order coherent -- is exactly the friction a queryable
item store removes. The value is in the **query path** ("what is open in arc X by
rank", "what runs next") and in **surviving context compaction**: the store is on
disk, not in a chat. Treat it as the single source of planning truth.

## The two roles and the one handover

This project runs an analysis role (reads code, plans, proposes) and an executor
role (applies ratified work). The store serves both:

- **Reading** (both roles): just read the checked-out tree. There is no service,
  no endpoint, no connector.
- **Writing from the web/analysis sandbox** (no push rights): make the edits in
  the sandbox clone, then emit a **patch or bundle** the operator applies locally.
  Never push, never assume credentials. See "Web path" below.
- **Writing from the executor (local)**: edit the working tree directly and commit.

The single handover between the roles is the **ratifying commit/merge**. That is
the cheapest *correct* handover, so lean on it rather than inventing side channels.

## Hard constraints (the project constitution)

- **Planning state lives only as checked-in markdown in the tree.** Diffable,
  PR-reviewable, single-source. No second store, no forge issues.
- **The durable store holds only tree-drift-invariant state.** Anything pinned to
  a working-tree hash (byte-exact before/after snippets, exact files-and-edits,
  exact grep gates) is *not* stored. A stored item carrying a stale byte-exact
  snippet is worse than no item: it trains false-alarm stop-and-report once the
  tree drifts. The full byte-exact instruction is authored **ephemerally** at
  execution time against the then-current pin and discarded after it lands.
- **Operator ratification is mandatory** between analysis and execution.
- **ADRs and D-decisions are permanent and append-only**, live **outside** this
  store, and are **never** touched here. See "ADR boundary".
- **Forge-agnostic**: the store is just git. GitHub today, gitea later -- nothing
  here depends on a specific forge.
- **All item content must be ASCII-only**: title, goal, acceptance_intent, and
  body text must contain only ASCII characters. Use plain prose without Unicode
  arrows, special symbols, or non-ASCII diacritics. This ensures reliable diffs,
  linting, and compatibility across tools and encodings.

## The store layout

```
roadmap/                 visible (not hidden): the point is diffability
  item-0042.md           one file per item, planning-state frontmatter + short body
  _order.md              the global cross-arc execution order (item IDs, line order)
  completed/             done items are moved here, keeping the active set small
    item-0017.md
```

## The model in one screen

Item frontmatter (full field reference in `references/schema.md`):

```yaml
---
id: item-0042                 # stable, referenceable in commits
status: proposed              # proposed | ratified | done
arcs: [output-model, image-from-step]   # one or more; arcs are query tags
rank: "0030"                  # numeric-sparse, zero-padded; orders WITHIN an arc
title: "..."                  # one line
goal: "..."                   # one-line end state, drift-invariant
acceptance_intent: "..."      # the INTENT of acceptance, never byte-exact greps
links: [ADR-046]   # pointers, never copies
execution_profile: { class: smallest, reasoning: none }   # optional, advisory
---
Short drift-invariant notes: rationale, open questions. No byte-exact snippets.
```

Two ordering axes, deliberately distinct:

- **`rank`** orders items *within* an arc. It answers "what is open in arc X, by
  rank". Numeric-sparse and zero-padded (`"0010"`, `"0020"`, ...), so you insert by
  taking the midpoint and never renumber neighbours.
- **`_order.md`** is the single cross-arc execution truth -- a flat list of item
  IDs in run order. It answers "what runs next". Because items can carry several
  arcs, arcs are treated as tags and this one global list decides sequence; that
  keeps "what's next" unambiguous and models arc-crossing moves cleanly.

Keep the two coherent in your head: an item can sit high in its arc by `rank` yet
late in global execution order, and that is fine.

## Status gate: proposed -> ratified -> done

- **Analysis** writes only `proposed`.
- **`proposed -> ratified` is the operator's call**, and the real gate is the
  ratifying commit/merge (enforced by branch protection / review, not by this
  skill). The status flip is bookkeeping that rides along with that merge. Do not
  invent an auto-ratify path; even a mechanical change can be mis-scoped, so the
  one human checkpoint stays. Make the merge cheap, not skippable.
- **Executor** consumes `ratified`, does the work, then writes `done` with a final
  summary; the item moves to `completed/` and is committed with the item id in the
  message.

## Commands

The script is bundled in THIS skill's own `scripts/` directory -- the folder
that contains this SKILL.md -- NOT at the repo root. The repo root holds only
the `roadmap/` store. Run from the repo root (so the default `--root roadmap`
finds the store) and invoke the script by the literal path for your environment:

```
# Executor (Claude Code, working in the repo):
python3 .claude/skills/roadmap-items/scripts/roadmap.py <command> [options]

# Analysis sandbox:
python3 /mnt/skills/user/roadmap-items/scripts/roadmap.py <command> [options]
```

`${CLAUDE_SKILL_DIR}` expands to the first path under Claude Code ONLY; it is
EMPTY in the analysis sandbox, so never rely on it there. If your CWD is not the
repo root, add `--root /abs/path/to/roadmap`. The examples below abbreviate the
chosen invocation as `roadmap.py`.

| Intent | Command |
| --- | --- |
| Create a proposed item | `new --title T --arcs a,b --goal G --acceptance A [--rank R] [--links ...] [--class C] [--reasoning R]` |
| Query items (active by default) | `list [--status ...] [--arc ...] [--all] [--sort rank\|id]` |
| Show the execution order | `order` |
| What runs next | `next` |
| Print one item verbatim | `show ID` |
| Advance status | `set-status ID ratified` |
| Edit fields | `update ID [--title ...] [--goal ...] [--acceptance ...] [--add-link ...] [--remove-link ...]` |
| Reprioritize within an arc | `rank ID --to 0035` or `rank ID --between ID_A ID_B` |
| Re-space an arc's ranks | `rescale ARC [--step 10]` |
| Change arc membership | `restructure ID --arcs a,b` / `--add-arc x` / `--remove-arc y` |
| Place in execution order | `reorder ID [--before ID] [--after ID] [--to-position N] [--remove]` |
| Retire a ratified item | `done ID --summary "..."` |
| Emit a `git am` patch (new items) | `emit-patch ID [ID ...] [-m MSG] [-o FILE]` |
| Emit a `git am` patch (edits/moves) | `emit-patch --baseline DIR [-m MSG] [-o FILE]` |

### Worked examples

Create an item that spans two arcs, then ask what is open in one of them:

```
roadmap.py new \
  --title "Add OutputRef disjunction to deploy.artifacts.from" \
  --arcs output-model,image-from-step \
  --goal "deploy.artifacts.from is a step|step+output disjunction" \
  --acceptance "CUE validates both ref shapes; goldens regenerate" \
  --links ADR-046 --class smallest --reasoning none

roadmap.py list --arc output-model --sort rank
```

Insert between two items without renumbering the rest, the way the prose roadmap
could not:

```
roadmap.py rank item-0042 --between item-0030 item-0040
# -> rank 0035; the neighbours are untouched
```

If two neighbours are adjacent (no integer gap), the command stops and tells you
to `rescale <arc>` first -- an explicit, operator-visible re-spacing, never a
silent cascade.

Ask what to execute next, get the planning context, then author the byte-exact
instruction ephemerally (do **not** write it back into the item):

```
roadmap.py next
```

## Web path: emit a patch, never push

When you are in the web/analysis sandbox, edit the items with the script as
usual, then hand the operator something they can apply locally. Do not push and
do not expect credentials. **Do not hand-roll the patch and do not shell out to
`git format-patch`** -- the `emit-patch` command builds a `git am`-consumable
mbox directly (pure stdlib, no git invoked), so this step is one command, not a
re-invented ritual.

For a **new task** (a freshly created item -- the common case), pass its id.
`new` only writes the item file, so the patch is a single additive new-file hunk:

```
roadmap.py new --title "..." --arcs a --goal "..." --acceptance "..."
# -> created item-0042
roadmap.py emit-patch item-0042 -m "roadmap: add item-0042" -o roadmap.patch
```

For **edits, reordering, or a `done`-move** (anything that touches existing files
like `_order.md` or moves an item into `completed/`), `emit-patch` needs the
pre-image. Snapshot the store right after cloning, make your edits, then diff
against the snapshot:

```
cp -r roadmap /tmp/roadmap-baseline       # snapshot at clone time, before editing
roadmap.py reorder item-0042 --before item-0030
roadmap.py done item-0017 --summary "..."
roadmap.py emit-patch --baseline /tmp/roadmap-baseline -m "roadmap: retire 0017" -o roadmap.patch
```

The operator applies it with `git am roadmap.patch`, and **that apply is the
commit that ratifies** -- which is why `emit-patch` writes the `From:`/`Subject:`
envelope (author and message are preserved into their tree). The index lines
carry real git blob SHAs, so `git am -3 roadmap.patch` can 3-way-recover if the
operator tree has drifted; a clean tree ignores them. Defaults: author is
`roadmap-bot <roadmap-bot@localhost>` (override with `--author "Name <email>"`),
output goes to stdout unless `-o FILE` is given. This asymmetry is intentional:
the read path is ungated, the write path is operator-gated.

If you genuinely need full history transfer rather than a single logical change
(multiple commits, binary content), fall back to `git bundle create
roadmap.bundle HEAD` by hand -- `emit-patch` deliberately models the
one-change-one-ratifying-apply path, not arbitrary history.

## ADR boundary (advisory redirect, not a hard wall)

If asked to change an ADR or a D-numbered decision, do not edit `docs/ADR-*` and
do not create files there. Redirect to the append-only ADR process ("annotate,
never rewrite") and keep working only inside `roadmap/`. This is advisory: the
real guarantee is that ADRs live outside `roadmap/` (out of this skill's reach)
plus the existing CI check on the ADR index. You are reminding, not enforcing.

## What is enforced vs what this skill only advises

This skill is the **advisory** layer: it teaches the schema and the operations.
The hard guarantees live in git/CI, not here:

- Operator-only ratification -> branch protection / merge review.
- ADR immutability -> existing CI check, plus the structural fact that ADRs are
  not under `roadmap/`.

Do not pretend the skill enforces these. Lean on the merge.

## Out of scope

- No hosted MCP server or connector. The data is files-in-git.
- No forge issues as the store (breaks diffability and single-source).
- Never touch ADRs, D-decisions, or the ADR index.
- No byte-exact instruction contracts in the durable store. Those are ephemeral.

## Reference files

- `references/schema.md` -- full frontmatter field reference, `_order.md` format,
  the rank/rescale rules, and the status model. Read it when a field's meaning or
  an edge case (no-gap insert, multi-arc ordering) is unclear.
- `references/example-item.md` -- a filled-in item to copy from.
- `assets/item-template.md` -- a blank item template.
