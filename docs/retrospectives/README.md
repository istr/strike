# Retrospectives

Dated retrospectives of the orchestrate-only development workflow: what a
change set, an audit, or an incident taught about how the human-AI loop is
run. They are the empirical record behind the workflow rules -- every
imperative in `AGENTS.md` and `AI-WORKFLOW.md` traces back to a concrete
failure or measurement, and this directory is where those are written down.
The collection doubles as source material for publishing the workflow model
itself.

Conventions:

- One file per retrospective, named `YYYY-MM-DD-<slug>.md`, date first so a
  plain listing is the chronology. US-English, ASCII only.
- Retrospectives are history: append-only in spirit. Corrections are added
  as dated annotations, never silent rewrites -- the same discipline as ADRs.
- A retrospective records findings, decisions, and their rationale at a
  point in time. It never owns planning state: open work it identifies is
  written into the `roadmap/` item store, and the retrospective points at
  the item ids.
- Pin every code claim to a commit SHA. Trees move; anchored claims stay
  checkable.

The review-time practices that produce these documents are described in
`docs/AI-REVIEW-AND-RETROSPECTIVES.md`.
