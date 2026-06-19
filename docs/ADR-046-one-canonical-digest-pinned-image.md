# ADR-046: A step with output produces exactly one canonical digest-pinned image

## Status

Accepted. Sharpens [ADR-026](ADR-026-containers-as-sole-inter-step-storage.md)
(containers as sole inter-step storage), [ADR-035](ADR-035-build-payload-in-engine.md)
(outputs are workdir-volume projections), and
[ADR-036](ADR-036-engine-native-input-delivery.md) (engine-native input
delivery) on the output and input model. Builds on
[ADR-045](ADR-045-execute-only-by-pinned-digest.md) (execute only by pinned
digest), extending its digest discipline to output and input pulls.

## Context

A step's output is wrapped into a content-addressed image under the step's
canonical tag `localhost/strike/<lane>/<step>`, keyed by step (ADR-026). Four
facts, verified against the tree, not assumed:

- A step's produced image is, by construction, the step's own image, addressed by
  step id. `#OutputSpec` nonetheless requires an `id` on every output, including
  that canonical image -- redundant, since the executable use references it by
  step, not by output name.

- **The current multi-output producer is defective.** Outputs are wrapped one at
  a time -- each becomes a fresh single-layer image and `ImageTag(id, <stepTag>)`
  moves the shared step tag onto it -- so after the loop the tag retains only the
  last output; earlier outputs lose their only name and become dangling. The
  consumer (`buildInputDelivery`) extracts each input from the step's tagged image
  by a per-output path (`OutputLayerName(output)`), already assuming one step
  image holding all outputs at distinct paths. Producer and consumer agree only
  for single-output steps. `fan_out_lane.yaml` (one producer, three file outputs,
  per-output consumers) exercises the broken case, yet the only test touching it
  runs every fixture through a mock engine and tolerates errors
  (`TestRunStep_RealLanePatterns_NoPanic`). No test runs it against a real engine
  with content verification, so the corruption is unobserved: a multi-output step
  silently delivers only its last output.

- **Integrity rides the manifest digest.** Both wrap paths (`loadTagVerify` for
  file/directory, `wrapImageFromReader` for image) compute the OCI manifest digest
  (`img.Digest()`) and verify it equals the engine-stored digest
  (`InspectDigest`); the registered `Artifact.Digest` is that manifest digest. The
  manifest digest is a Merkle root over the config and layer descriptors, so it
  already commits to every layer digest. No layer digest is checked separately,
  and none needs to be.

- **The consumer still fetches by the mutable tag.** `buildInputDelivery` pulls
  the producer image by `WrapTag`, not by the manifest digest it just registered.
  That tag dependency is at once the root of the last-write-wins corruption and a
  digest-pinning gap against ADR-045's execute-by-digest rule.

## Decision

A step with output produces **exactly one canonical, digest-pinned image**. Three
properties define what producer and consumer can rely on:

**(a) Exactly one image.** A step's outputs are assembled into one
content-addressed step image -- a built rootfs, or named layers (one per content
output at its `OutputLayerName`), or both. This replaces the per-output,
tag-moving wrap and fixes the multi-output defect by construction.

**(b) Digest-pinned.** The manifest digest is the single integrity anchor: a
Merkle root over config and layer descriptors, so it commits to every layer; no
layer digest is checked separately (redundant given the manifest commits to them,
and insufficient alone). Every use -- running the image or extracting content from
it -- pulls by `repo@sha256:<manifestDigest>`, never by the mutable tag. This
extends ADR-045's execute-by-digest rule to the consumer/input side; the tag
remains a cache-existence key only.

**(c) Canonically addressable.** The image is addressed by step (the tag repo)
plus its manifest digest, independent of any output identifier. The executable use
needs no output id (it resolves by step); content use names a layer.

That one image is **either executable or content-addressable by subsequent
steps**: `imageFromStep` runs it as a base; `inputs.from` extracts a named layer
from it.

**This ADR deliberately does not anchor a structural image-vs-content
disjunction.** After (a)-(c), an executable image and a content image are
structurally indistinguishable -- both are content-addressed step images pulled by
manifest digest. Which role a given step's image plays is current policy
(`imageFromStep` for execution, `inputs.from` for content), not a structural
property. Anchoring the contract rather than the disjunction leaves a later
relaxation -- one step image serving both roles -- reachable without revisiting
this decision. How outputs are declared, named, and typed in the schema is a
downstream concern this ADR enables but does not cement here.

## Consequences

- The last-write-wins defect is closed at the root, twice: producer-side (one
  step image, not N) and consumer-side (pull by manifest digest, no trust in the
  mutable tag). Either alone would close it; together they make the tag
  non-load-bearing for content. A real-engine content-verifying test over
  `fan_out_lane.yaml` lands with the change, closing the test gap that hid it.
- The manifest digest is the only integrity anchor; the contract is
  layer-count-agnostic (a runnable image keeps its build's layers; content outputs
  are one layer each).
- `ImageFromEdge` sheds `FromOutput`; the executable use resolves by step.
- The executable/content distinction is policy, not structure, so a later opening
  (one step image serving both roles) stays reachable with no structural change.
- Ripples (implementation, separate instruction): `wrapOutputs`/
  `wrapArchivedOutput` (assemble one step image); `buildInputDelivery`/
  `producerTar`/`buildImageMount` (pull by manifest digest, not `WrapTag`);
  `resolveImageDigest`/`dag.go` (`ImageFromEdge`); the output-declaration schema in
  `specs/lane.cue` and `parse.go`; fixtures; tests; annotations to ADR-026/035/036
  and `tools/lintfrom`.

## Principles

- **External references are digest-pinned** -- ADR-045's execute-by-digest rule
  now governs output and input pulls too; nothing is fetched by a mutable tag, and
  the manifest digest is the one anchor (it transitively covers the layers).
- **Containers are the only storage** -- one step image (ADR-026) carries the run
  base or the named content; the producer is brought into line with the
  single-image model the consumer already reads from.
- **Code is liability** -- one assemble-and-tag replaces N per-output wraps; the
  consumer drops tag-based fetch; `ImageFromEdge` drops a field; the ADR avoids
  over-encoding a disjunction the structure does not require.
- **Reproducibility is enforced** -- a deterministic single step image with stable
  layer ordering replaces a last-write-wins tag whose content depended on output
  declaration order.
- **Enforcement is structural, not discretionary** -- the one-image contract and
  the digest pull are structural; the executable/content split is named as policy,
  not cemented into the schema.
