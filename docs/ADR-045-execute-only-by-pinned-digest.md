# ADR-045: Steps execute images only by pinned content digest

## Status

Accepted.

## Context

An image reference reaches a step in three roles, and two of the three were
already pinned to a control-plane (CP) computed content digest before this
decision:

- **Externally declared base images** are digest-pinned at the schema boundary:
  `image@sha256:...` is the only accepted form and `image:latest` is a parse
  error (DESIGN-PRINCIPLES "External references are digest-pinned"; ADR-011).
- **Step inputs** are digest-checked intra-run by the CP: the controller
  recomputes the content hash and matches the declared pin, so a lying engine, a
  MITM, and a hostile registry fail the same check (ADR-037, "Input reference
  integrity", layer V).

The third role -- a step's base image taken from a previous step's produced image
(`imageFrom`) -- was not pinned at execution. The produced image was loaded into
the engine's local store under the cache tag
`localhost/strike/<lane>/<step>:<spec_hash>` (ADR-026), and the consuming step
was executed against that tag. ADR-026 itself states that these tags are lookup
keys, not cryptographic anchors, and that inter-step DAG references record the
manifest digest -- but the execution path used the tag as the anchor and relied
on the engine's tag-to-digest mapping to resolve which bytes to run.

That reliance is the defect. The CP seals the produced image's manifest digest
into the consuming step's identity (it is folded into the step spec hash and
recorded in the attestation), which is a layer-V (CP-observed) claim. Execution
against a mutable local tag does not enforce that claim: the tag can be made to
resolve to different content -- by local image-store mutation (a co-tenant, or a
concurrent or prior lane sharing the engine), which is below the threshold of the
engine "lying" over its API, or by a non-reproducible producer leaving a shared
tag pointing at another run's image. The attestation would then carry the
legitimate digest while the step executed a different base. A V claim that is
asserted but not enforced is a false V assurance, which is worse than an honest
engine-context (E) assertion.

## Decision

Every image a step executes is referenced **only by a CP-computed content
(manifest) digest**. This holds uniformly for externally declared base images and
for lane-generated base images; there is no second execution-reference form.

- **One execution-reference form.** A step's base image is always passed to the
  engine as `<locator>@sha256:<digest>`. The execute-by-tag path is removed; no
  step is ever executed against a mutable tag.
- **Lane-generated images go through a CP digest roundtrip.** A produced image
  consumed as a base is materialized through the CP: the CP computes the manifest
  digest over the bytes it observed crossing the engine boundary and publishes
  the image content-addressed, then the consuming step pulls and runs that
  digest. The components already exist (the CP-side content-addressed write and
  the engine pull-by-digest used for externally declared images); this is a
  rewiring, not new machinery.
- **The engine tag-to-digest mapping leaves the execution-trust path.** Tags
  (`localhost/strike/<lane>/<step>:<spec_hash>`, ADR-026) remain cache-existence
  lookup keys -- an engine-context optimization -- and are never the execution
  anchor.

This invariant is applied to all lane-generated executable images at once, so
that "execute by a reference other than a pinned content digest" is structurally
unrepresentable rather than absent case by case.

## Why this closes imageFrom in layer V

The base-image execution reference becomes the CP-sealed content digest, which is
a CP-observed (layer-V) value. The binding "this step was built on digest D" is
therefore enforced, not merely asserted: a pull-by-digest recomputes the digest
on fetch, so a divergent local image fails closed before the step runs. The
engine's tag-to-digest resolution -- engine-context, and reachable below the
engine-lying threshold via local-store mutation -- is removed from the path.

With this, the lane-generated base attains parity with the externally declared
digest-pinned base. The only residual is the irreducible boundary that every base
image shares: whether the engine truly materializes the pinned bytes as the
container root filesystem is engine-dependent (layer E) and is not enlarged by
this decision. What V seals is "the CP observed these exact bytes and pinned the
step to that digest"; what remains E is the engine's faithful execution of those
bytes -- the same split that already governs an externally declared
`image@sha256:...` base. Tags continue to serve as lookup keys exactly as ADR-026
intended; they never carry trust.

## Consequences

- The `imageFrom` execution path is rewired to pin by digest. The implementation
  lands as the item-7 sequence: first the execution-by-digest hardening on the
  current schema, then the `imageFrom` schema rebuild. This ADR is the decision
  those instructions cite.
- The executor's tag-override branch (the `ImageRef`-by-tag path) is eliminated;
  a single digest-pinned execution path remains for all steps.
- A lane-generated base is published content-addressed via the existing CP push
  and pulled by digest via the existing pull path. No new dependency, no new
  component.
- ADR-026's tag scheme is unchanged and is annotated with a forward pointer: tags
  stay cache-existence keys; execution pins by digest.
- `imageFrom` references the producing step's declared, CP-digest-pinned image
  artifact, not an engine-committed root filesystem; the produced image is a
  fully declared output the CP validates, so the indirection through an output
  artifact is sound where an implicit root-filesystem commit would not be.

## Principles

- **External references are digest-pinned** -- extended from declaration to
  execution: the pin is now also the only reference form a step is executed
  against, lane-generated images included. This generalizes ADR-026's "every
  inter-step reference is an image digest" from what is recorded to what is run.
- **Runtime is attested** -- the base-image digest the attestation seals is
  enforced at execution, closing the gap between the sealed claim and the
  executed image.
- **Enforcement is structural, not discretionary** -- the non-digest execution
  path is removed, so the divergence class cannot be expressed rather than being
  guarded against per case.
- **Code is liability** -- one execution-reference form replaces two; the
  tag-execution path and its engine-resolver dependence are deleted.
