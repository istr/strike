# ADR-010: Typed DAG Edges Carry Resolved References

## Status

Accepted.

## Context

Steps in a strike lane reference each other through string fields: an
input declares `from: "build.binary"`, a pack file declares
`from: "compile.tree"`, a deploy artifact declares `from: "pack.image"`.
Early in the project, these strings were re-parsed at every consumer:
the executor split `"build.binary"` into step name and output name,
looked up the step, looked up the output, and proceeded.

Re-parsing the same string in multiple places produces three failure
modes:

- *Semantic divergence.* The DAG topology is computed from the
  strings during validation. The executor re-parses the same strings
  during execution. If the two parses disagree (different normalization,
  different error handling, different edge cases), execution can take
  edges that the topological sort did not see.
- *Repeated lookups.* Every consumer pays the resolution cost; the
  resolver code is duplicated; bugs in resolution multiply.
- *Untyped data crossing package boundaries.* The string `"build.binary"`
  carries no type information. A function that takes such a string
  cannot enforce that the reference is well-formed; the compiler
  accepts any string.

The fix is to resolve references once, store them as typed edges in
the DAG, and have all consumers read the typed form.

## Decision

`lane.Build` populates four typed edge maps on the `DAG` struct:

- `InputEdges map[string][]InputEdge` -- per consuming step, the list
  of resolved input edges (`LocalName`, `Mount`, `FromStep *Step`,
  `FromOutput *OutputSpec`).
- `PackFileEdges map[string][]PackFileEdge` -- per packing step, the
  list of resolved file edges (`Dest`, `FromStep`, `FromOutput`).
- `DeployEdges map[string][]DeployArtifactEdge` -- per deploy step,
  the list of resolved artifact edges (`ArtifactName`, `FromStep`,
  `FromOutput`).
- `ImageFromEdges map[string]ImageFromEdge` -- per step using
  `image_from`, the resolved edge.

`FromStep` and `FromOutput` are guaranteed non-nil by `Build`. The
string parser `parseRef` is package-private to `lane` and is not
exported. Consumers outside `internal/lane` cannot re-resolve string
references, because the function that does so is not visible to them.

A custom AST-based linter rejects reads of the underlying `.From`
string field outside `internal/lane`. The DAG carries the canonical
truth; consumers consume the typed edges.

## Consequences

- Adding a new edge kind is a deliberate two-step process: define a
  new edge type with non-nil pointer guarantees, populate it in
  `Build`. Consumers cannot accidentally pre-empt the schema by
  re-parsing strings.
- Mount disjointness validation, provenance path validation, and
  topological sort all read the same edge data. Divergence between
  validation and execution is structurally impossible.
- The DAG's `Build` function is the only place that needs to know
  the format of reference strings. Consumers get type-checked
  pointers.
- The linter that enforces this is project-specific, not a
  community linter. Its existence is a deliberate cost paid once to
  avoid a class of bugs that would otherwise recur.

## Principles

- Code is liability (one resolver, not many)
- CUE first (the edge types are defined by the lane schema, not
  invented at the consumer)
- Reproducibility is enforced (validation and execution see the
  same edges)
