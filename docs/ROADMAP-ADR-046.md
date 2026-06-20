# ADR-046 Implementation Roadmap

## Status: IN PROGRESS (file-topology reorg landed at 8de46bd; output-model schema settled; wire instruction next)

[ADR-046](ADR-046-one-canonical-digest-pinned-image.md) is accepted. A step with
output produces exactly one canonical, digest-pinned image; that image is either
executable (a run base via `imageFromStep`) or content-addressable (named layers
via `inputs.from`) by subsequent steps. This roadmap owns the implementation arc.
It absorbs the former cross-roadmap execution-order item 7b (the `imageFromStep`
rebuild) and folds in the producer one-image fix and the consumer pull-by-digest
that the ADR's investigation surfaced.

The predecessor, item 7a (imageFrom execution hardening, layer V), landed with
ADR-045: a step executes a lane-generated base image only by its CP-computed
manifest digest. This arc builds on that hardened base.

## Decisions (ratified)

- **D1** -- `imageFromStep` runs on the producing step's declared,
  CP-digest-pinned image artifact; not root-filesystem inheritance.
- **D2** -- a step declares exactly one image output XOR any number of non-image
  outputs, never both; the same-step-is-both-base-and-copy-source hybrid is
  YAGNI, recorded as a re-open gate.
- **D3** -- a step executes only a CP-digest-pinned image (lane-generated base
  included); recorded as ADR-045.
- **D4** -- sequencing: 7a (execution hardening) before 7b (schema rebuild).
- **D5 (ADR-046 contract)** -- a step with output produces exactly one canonical
  image, defined by three properties: (a) exactly one image; (b) digest-pinned,
  with the manifest digest as the single integrity anchor (a Merkle root over
  config and layer descriptors, so no separate layer-digest check); (c)
  canonically addressable by step plus manifest digest, independent of any output
  id. The image is executable or content-addressable by subsequent steps.
- **D6 (producer one-image fix)** -- the producer assembles one step image holding
  each file/directory output as a named layer at its `OutputLayerName`, replacing
  the per-output, tag-moving wrap. This fixes the verified multi-output
  last-write-wins defect by construction (`fan_out_lane.yaml` currently delivers
  only its last output, unobserved because the only test touching it tolerates
  errors against a mock engine). A real-engine content-verifying fan-out test
  lands as the regression guard.
- **D7 (consumer pull-by-digest)** -- output and input images are pulled only by
  `repo@sha256:<manifestDigest>`, never by the mutable `WrapTag`; ADR-045's
  execute-by-digest rule extends to the consumer/input side. The tag is a
  cache-existence key only. This closes the last-write-wins defect on the consumer
  side as well, making the tag non-load-bearing for content.
- **D8 (XOR is policy, not structure)** -- after D5--D7 an executable image and a
  content image are structurally indistinguishable. The image-vs-content
  distinction is current policy (`imageFromStep` for execution, `inputs.from` for
  named content), not a schema-anchored disjunction; this is D2's re-open gate
  made explicit, leaving a later opening (one step image serving both roles)
  reachable without structural change.
- **D9 (wire vs internal API -- two layers)** -- the specs separate two layers.
  Layer 1 is the lane.yaml wire format (CUE parse-time validated, `specs/lane.cue`);
  layer 2 is the internal typed API (`specs/artifact-api.cue`), carrying runtime
  properties -- above all the content-addressed image-ref -- that cannot exist at
  authoring time and so never appear in the wire. Per ADR-004 both are
  CUE-formalized. Where the wire maps 1:1 to the internal API it may inherit it;
  never the reverse. Machine-enforced direction (a separate package or a CUE lint)
  is deferred; the file boundary is the first step.
- **D10 (wire output model -- structural XOR split)** -- the wire declares a
  singular `output` (the step image: no id, referenced by step) XOR plural
  `outputs` (named file/directory outputs, referenced by `inputs.from {step,
  output}`). `imageFromStep: #Identifier` replaces `#Step.imageFrom`. The
  image-vs-content XOR is wire policy, enforced structurally in the wire schema;
  D8's "not a structural property" refers to the image artifact (layer 2), not the
  wire.
- **D11 (internal resolved handle)** -- `#OutputHandle{step, imageRef, layerRef?}`
  (layer 2) is the universal resolved handoff. No `layerRef` = whole image
  (execution via `imageFromStep`, image deploy); `layerRef` set = a named content
  layer at its `OutputLayerName` (`inputs.from`, `pack.files`, file deploy).
  `imageFromStep`, `inputs`, `pack`, and `deploy` all resolve to it at runtime; it
  carries the manifest digest, so D7's pull-by-digest is intrinsic.
- **D12 (deploy artifact ref -- wire disjunction)** -- `deploy.artifacts.from`
  becomes a wire disjunction: step-only (an image, by step) XOR `{step, output}`
  (a file/directory, by name), realized with the verified `@go(-)` + hand-sewn
  glue pattern (as `#DeployMethod`). This corrects the prior conflation, where
  deploy referenced a step image by a non-existent output id.
- **D13 (file-topology reorg -- LANDED 8de46bd)** -- the internal `#Artifact`
  carrier moved from `lane.cue` (wire) into `specs/artifact-api.cue` (package
  lane, internal API), drawing the layer boundary; gengotypes-neutral and
  behavior-neutral. `#OutputHandle` (D11) lands in this file in the wire arc.

## What needs to be implemented

1. **Establish ADR-046.** ADR file created and wired into `ADR-INDEX.md`;
   forward-pointer annotations added to ADR-026/035/036. (Lands with the
   establish instruction that also creates this roadmap.)

2. **Output-model schema (ratification-gated).** Settle, with the operator, the
   `specs/lane.cue` shape that realizes the contract: the canonical image output
   (referenced by step, no id) versus named file/directory outputs (referenced by
   `inputs.from {step, output}`), and the `imageFromStep: #Identifier` replacement
   for `#Step.imageFrom`. Per the schema-first rule this is operator-ratified
   before any wire instruction. Open question F1 (below) is settled here.

   **SETTLED** -- the ratified shape is recorded as D9--D12 (two-layer
   wire/internal split, id-less wire image output referenced by step, internal
   `#OutputHandle`, deploy-ref disjunction); F1 is resolved.

3. **Wire the model (one coherent instruction).** On the ratified schema:
   - `imageFromStep` resolution in `resolveImageDigest`/`dag.go`; `ImageFromEdge`
     sheds `FromOutput` (execute-only consumer; resolve by step).
   - Producer one-image assembly in `wrapOutputs`/`wrapArchivedOutput` (D6).
   - Consumer pull-by-digest in
     `buildInputDelivery`/`producerTar`/`buildImageMount` (D7).
   - `parse.go` XOR and any per-step output constraint.
   - Fixtures and tests, including the real-engine content-verifying fan-out test.

   **Expanded by D9--D13:** also introduce the internal `#OutputHandle` (D11) in
   `artifact-api.cue` and convert `dag.go` edges + `run.go` runtime resolution to
   it; land the `#ArtifactRef` wire disjunction via `@go(-)` + glue (D12); the
   wire output split (id-less `output` XOR named `outputs`) is D10. The
   file-topology reorg (D13) landed at `8de46bd` as the prep step.

## Open questions

- **F1 (gengotypes) -- RESOLVED.** `imageFromStep?: #Identifier @go(ImageFromStep,type=string,optional=nillable)`
  generates a bare `string`, not `*string`: `optional=nillable` is ignored when
  `type=string` forces the Go type. The presence check is therefore `!= ""`, not
  `!= nil`; `#Identifier` excludes the empty string, so `""` is an unambiguous
  "absent". Measured against the parent of `8de46bd`.

## Sequencing

ADR-046 establish (with this roadmap) -> output-model schema ratification (item 2,
settling F1) -> the wire instruction (item 3) on the ratified schema. The engine /
transport cluster (cross-roadmap execution-order items 8--11) is independent and
unblocked by this arc.

## References

- `docs/ADR-046-one-canonical-digest-pinned-image.md` -- governing ADR
- `docs/ADR-045-execute-only-by-pinned-digest.md` -- the layer-V hardening (7a)
  this arc builds on
- `docs/ADR-026-containers-as-sole-inter-step-storage.md`,
  `docs/ADR-035-build-payload-in-engine.md`,
  `docs/ADR-036-engine-native-input-delivery.md` -- the storage / output / input
  ADRs ADR-046 sharpens
- `docs/ROADMAP-STATUS.md` -- cross-roadmap execution order (points here for this
  arc)
