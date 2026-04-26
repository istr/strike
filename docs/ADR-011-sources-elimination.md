# ADR-011: Host Filesystem Cannot Enter the DAG

## Status

Accepted.

## Context

Early lane definitions allowed a step to declare `sources:`, a list of
host filesystem paths to mount into the step container. The intent was
convenience: a developer could iterate on local source files without
first packaging them as a step output.

This produced a structural problem. Every other data flow in strike
enters a step through a typed edge in the DAG: a previous step's
output becomes the next step's input, with a content digest and an
edge entry. Sources bypassed this entirely. A host path was read at
execution time, with no content addressing, no DAG edge, and no place
in the spec hash that determines cache lookup. The net effect was a
hole in the type system: an unsigned, unaddressed input that could
silently change between runs.

The right shape was visible in retrospect: every input must be the
output of a step, including inputs that originate on the host. A
"source" step that produces a content-addressed tree is the same
shape as any other step, with a typed output that downstream
consumers can reference.

## Decision

The `sources:` field is removed from the lane schema entirely.
`lane.Parse` rejects YAML containing this field at parse time.

Every data flow into a step enters as an `InputEdge` from another
step's `OutputSpec`. There is no other entry point.

A step that needs to bring host filesystem content into the DAG runs
a containerized capture step (e.g. `image: alpine/git`,
`args: [git, clone, --depth, "1", URL, /out/tree]`,
`outputs: [tree]`). This step has the same security profile as any
other (cap-drop, read-only root, declared network), produces a
content-addressed output, and has its own provenance record.

`lane.Build` enforces mount disjointness: two input mounts cannot
overlap (identical paths or one a path-prefix of the other). When a
step needs multiple sources to appear at related container paths
(e.g. a tree at `/work` with dependencies at `/work/node_modules`),
the operator composes them in a separate pack step that produces a
single image output, then mounts that image.

## Consequences

- The lane schema gains no new field; an existing field is removed.
  Schema regression is not a concern in pre-beta, and the operator
  has confirmed nothing in production depends on the old shape.
- A class of "this works on my machine" bugs is structurally
  closed: any input not visible in the DAG is also not visible to
  the execution. A working lane in CI runs identically locally.
- The diagnostic for a missing `sources` field is "unknown field":
  a parse error, not a runtime warning, and not a silent mount of
  empty content.
- Composition of related mounts becomes explicit: the operator must
  pack them, not declare them as sibling mounts. This pushes
  composition into a content-addressed boundary where it can be
  reasoned about.

## Principles

- External references are digest-pinned (every input is content-
  addressed, including ones that originated on the host)
- Code is liability (one input mechanism, not two)
- Reproducibility is enforced (no host state leaks past validation)
