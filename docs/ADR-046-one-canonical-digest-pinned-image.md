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

  > **Refinement (ADR-046 wire arc).** Confirmed and sharpened. The wire image
  > output is id-less and referenced purely by step -- not only by `imageFromStep`
  > (execution) but also by the image arm of `deploy.artifacts.from` (deploy), a
  > consumer the original "executable use" phrasing did not name. Both resolve at
  > runtime to the internal `#OutputHandle{step, imageRef, layerRef?}` (layer 2),
  > which carries the manifest digest the wire cannot.

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

> **Refinement (ADR-046 wire arc).** "Structural" here is the image-artifact /
> runtime level: an executable image and a content image are the same kind of
> content-addressed artifact, and the runtime manifest digest (image-ref) is a
> layer-2 property that never appears in the wire. The wire format (layer 1, CUE
> parse-time) does carry the image-vs-content policy as a structural XOR split --
> a singular id-less `output` (image) versus plural named `outputs`
> (file/directory). The two layers are formalized in separate files per ADR-004
> (`specs/lane.cue` wire; `specs/artifact-api.cue` internal API, home of the
> resolved `#OutputHandle`); the wire may inherit the internal API where they
> coincide, never the reverse. The re-open gate (one step image, both roles) is
> then a wire-policy relaxation, the implementation already being layer-uniform.

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

## Amendment -- output-key vocabulary (post-implementation)

A retrospective on implementing this ADR found a single root cause behind
repeated mis-specification: the output model ends with **three distinct keys**
that both natural language and the code symbols collapsed onto one word
("layer" / "name"). The Decision text above also seeded the confusion --
"(a) ... **named layers** (one per content output at its `OutputLayerName`)"
couples a layer's name to a path-derived value, while the implementation makes
layer identity the output id and treats `OutputLayerName` as a separate,
in-layer path concern. One overloaded word for three concepts was the cause.

Equally, the original Decision specified the output **identity** (the output id)
and the integrity anchor (the manifest digest) but did not name the
engine-boundary **selection mechanism** -- how a consumer actually finds a
layer inside a step image after a container-engine round-trip. That mechanism
(the OCI `diff_id`) is recorded here.

The three keys are distinct and are named for their level:

- **identity** -- the output id (`out.ID`, an `#Identifier`); it addresses the
  output, and thereby its layer, across steps. Carried as **`OutputID`**
  (formerly `LayerID`).
- **content root** -- the top-level path segment under which an output's content
  is rooted inside its OCI layer; a producer/consumer re-rooting convention the
  engine never sees. Carried as **`OutputContentPrefix`** (formerly
  `OutputLayerName`).
- **engine selection key** -- the OCI `rootfs.diff_ids` uncompressed-content
  digest; the only per-layer key stable across a container-engine load/save
  round-trip, and the key a consumer selects by (`LayerByDiffID`). Carried as
  **`LayerDiffID`** (unchanged -- "Layer" is correct here; this is a genuine
  OCI-layer property). Reserving "Layer" for this one real layer-level key
  removes the overload.

The layer-descriptor annotation key becomes **`dev.strike.output.id`** (its
value is the output id). The annotation is advisory only: a container runtime
strips descriptor annotations and re-compresses blobs on load, so the consumer
selects the layer by its `diff_id`, never by the annotation.

**Supersedes, in the Decision above:** the phrase "named layers (one per content
output at its `OutputLayerName`)" is read as "one content layer per output, each
rooted at its `OutputContentPrefix`"; a layer's identity is the output id, not
its content root.

This amendment changes vocabulary, not behavior. The implementation is scheduled
as a separate roadmap item ahead of the spec-layering file reorg, so that reorg
moves already-corrected names.

## Amendment -- digest collapse (item-0039)

The internal structured `DigestRef` and the wire/internal bridge it required are
removed in favor of the single representation-neutral `primitive.Digest` wire
value. The algorithm is fixed to sha256 (ADR-008): every digest strike produces
or consumes -- ggcr image and manifest digests, podman inspect output, in-toto
subjects -- is sha256, and the OCI ecosystem treats sha256 as canonical (sha512
is an optional MAY, sha384 is unregistered), so the structured {algorithm, hex}
pair carried no information the wire string did not already imply. Validation
survives as the slim boundary helper `primitive.ParseDigest`; the bare-hex
projection survives as `primitive.Digest.Hex()`, with `primitive.DigestFromHex`
as its inverse constructor -- the one chokepoint that prepends the `sha256:`
prefix to a freshly computed hex body. This changes representation, not behavior:
the wire form is byte-identical, so the golden fixtures are unchanged.

## Amendment -- lintfrom retired (item-0068)

The `tools/lintfrom` linter and its `lint-from` make gate are removed. lintfrom
forbade code outside `internal/lane` from reading the wire `.From` field on
`InputRef`, `PackFile`, and `ArtifactRef`, on the premise that after `lane.Build`
the resolved DAG edges were the only valid consumer API. The DAG-reduction arc
(item-0068) deletes those resolved edge structs and their maps: consumers now
read the lane iterators (`Inputs`, `PackFiles`, `DeployArtifacts`) and their
typed `#OutputRef` `.From` directly, which is the sanctioned consumer API. The
linter's premise no longer holds, and it would forbid exactly that API.

The hazard lintfrom originally guarded -- consumers parsing a dotted
`"step.output"` string ref with scattered ad hoc splitting -- had already been
eliminated earlier, when producer references were unified on the typed
`#OutputRef`. A `.From.Step` read is then a typed field access with no parse
step, so the compiler already provides structurally what the linter enforced by
discipline. Removing the tool follows the code-is-liability principle: a gate
that protects a deleted API and blocks its replacement is pure liability. This
changes tooling, not behavior; goldens and attestations are unchanged.
