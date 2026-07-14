# ADR-051: Deploy is the sealing point -- a signed, SBOM'd subject over the deployed payload

## Status

Accepted. Refines [ADR-039](ADR-039-deploy-step-as-attestation-root.md)
(deploy is the attestation root) by fixing what the root actually seals, and
[ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md) by moving
SBOM generation (D1) from the pack step to the deploy step and by realizing
the control-plane push (D4) for locally produced images. Consistent with
[ADR-043](ADR-043-retire-keyed-image-signing-and-rekor-v1.md) (pack outputs
are unsigned intermediates), [ADR-037](ADR-037-two-engine-trust-layers.md)
(the V/E layering), [ADR-046](ADR-046-one-canonical-digest-pinned-image.md)
(one canonical digest-pinned image), [ADR-016](ADR-016-drift-recording-posture.md)
(state recording, record-not-react), and
[ADR-019](ADR-019-sbom-as-oci-referrer.md) (SBOM as a referrer on the subject
digest). Names the transport-deploy family as a deferred successor grounded
in [ADR-038](ADR-038-protocol-mediated-ssh.md) D1. Makes breaking lane-schema
changes; acceptable pre-beta, no migration.

## Context

The build/pack/deploy field structure predates the V/E clarity that
ADR-037 established. Grounding the implementation against that clarity found
a model that does not hold together:

- The registry push ran through the engine (`Engine.ImagePush`), so a pushed
  image was an engine-asserted fact (Layer E), contradicting ADR-040 D4 ("the
  engine never pushes"). The push target came from a lane-wide `registry`
  field, and its addressing was delegated to the client library's routing
  rather than owned by strike.
- `DeploySpec.artifacts` was resolved only for the attestation and was never
  passed to any method executor. Across all three deploy methods the thing
  attested and the thing actually deployed were bound by convention, not by
  construction: the registry method copied a separate string source, the
  kubernetes method applied manifests piped from stdin, and the custom method
  ran an arbitrary container. The attestation could claim "deployed artifact
  A" while the method delivered something else.
- SBOM generation lived in the pack step, over the assembled image. A
  build-produced image that was later published received no SBOM at all, and
  cataloging ran for pack intermediates that are never published.
- The deploy region of the schema mixed unrelated concerns: an attestation
  target identity, an artifact reference shared with inputs and pack, the
  state-recording captures, a dead `source.gitImage` field with no consumer,
  and a step-level provenance declaration physically misplaced among the
  deploy types.

The forces are the project's own principles applied to the deploy seam: a
published artifact must be a Layer-V claim (produced from bytes the control
plane holds), what is attested must be what is delivered, and every line of
delegated addressing or unbound declaration is attack surface and liability.

## Decision

### D1 -- Deploy is the sole sealing point; build and pack are pure producers

A build step runs a container and produces a content-addressed payload; its
wrapping is deterministic (ADR-035) but its content is tool-dependent. A pack
step assembles a payload as a pure deterministic function of digest-pinned
inputs; its content is byte-reproducible by construction (Layer V via
reproducibility). Neither step signs or SBOMs its output -- both remain
unsigned intermediates (ADR-043). Signing, SBOM generation, push, and
attestation happen once, at deploy, over the deployed payload.

### D2 -- Every deploy produces one signed, SBOM'd subject over the deployed payload

The deploy subject is a content-addressed image; the signature and the SBOM
cover its manifest digest. The deployed payload is taken from the deploy's
`artifacts` -- the strike-controlled, digest-pinned inputs -- so what is
attested is what is deployed, by construction. The state-recording capture
report is bound to the subject as a referrer on the subject digest (ADR-019),
not baked into the payload: the payload is immutable and predates the capture,
so it cannot contain a report about its own deployment. One subject concept,
one binding mechanism (referrer), a subject origin that varies by method.

### D3 -- SBOM generation moves from pack to deploy, over the sealed artifact

The control plane catalogs the sealed artifact in-process and emits the SBOM
at deploy time, refining ADR-040 D1 from pack-implemented to deploy-generated.
The cataloging code moves out of the pack step into the deploy path. This is
chosen over generating the SBOM in pack for four reasons: a build-produced
published image would otherwise carry no SBOM and would require a no-op pack
step to acquire one; no SBOM is produced for intermediates that are never
published (ADR-043-coherent); coverage is uniform across producers; and it
matches ADR-040 D1 literally -- the SBOM is over "the same bytes it pushes".
The SBOM stays canonical (deterministic serial number, SOURCE_DATE_EPOCH,
stable ordering), so a deploy-time SBOM over a reproducible pack payload is
itself byte-reproducible; the reproducibility guarantee lives in the payload
(pack), and the SBOM inherits it wherever the subject is a pack output.

### D4 -- The control plane owns the push; the engine never pushes

The control plane pushes the payload to the target with go-containerregistry
remote.Write, and the pushed registry digest is the signed subject -- the
signature covers the artifact as it exists in the registry (ADR-040 D4). The
engine-mediated push is removed. The lane-wide `registry` field is removed: a
push target is a per-deploy property, not a lane constant, and different
deploys may target different endpoints. strike validates the push destination
itself rather than delegating its interpretation to the client library.

### D5 -- Deploy methods: registry and kubernetes are in V, transport is a deferred successor, custom is removed

- **registry**: the control plane writes the payload image to the target; the
  subject is the pushed image. The capture set is typically empty: the
  transparency log plus the target identity (D6) already is the deployment
  versioning chain of an address, reconstructible without reading the
  registry. A registry-inventory capture would duplicate that chain from a
  weaker, race-prone, network-read source and is not part of the core model.
- **kubernetes**: the applied manifests are supplied from `artifacts`, not
  from stdin, so the payload is control-plane-controlled and in V; the apply
  is mediated; the capture set is the pre/post cluster state (ADR-016). The
  stdin path is removed as a V condition.
- **transport family** (rsync, scp, sftp, and git over SSH): the intended
  successor to custom for delivering artifacts to a remote endpoint. It is in
  V by four separable parts -- payload content from the digest pin, not from
  the wire; a verified endpoint host key and an allowlisted protocol
  (observed, Layer V); step attribution (engine-asserted, Layer E); and an
  optional remote post-state capture reporting what the remote holds. It is
  deferred to the ADR-038 D1 protocol-mediated front and is not built in this
  arc; the deploy path continues to reject SSH peers until that front lands.
- **custom is removed.** An arbitrary container action over an arbitrary
  transport is exactly the arbitrary command that ADR-038 D1 refuses. Its
  effect is out of V: the capsule records connection identity, not the
  application effect (ADR-038 D6/D7 relay the payload opaquely and do not
  parse protocol semantics). It has no strike-controlled payload to sign or
  catalog, so it cannot satisfy D2. Its intended use case survives as the
  transport family.

### D6 -- The deploy field structure: artifacts is the subject; redundant, dead, and misplaced fields are removed

- `DeploySpec.artifacts` is the deployed payload and the attestation subject,
  not an attestation-only side declaration. For a registry deploy it resolves
  to exactly one produced image (a step-image reference), the single subject
  the push writes and the signature covers.
- `DeployRegistry.source` is removed: it was a parallel string declaration of
  the same image that `artifacts` already carries.
- The registry-to-registry promote (copying an existing registry image named
  by a source reference to a target) is removed. It is not an ADR goal; its
  one distinct property is preserving a foreign digest while re-homing it,
  which is "attest a copy of bytes someone else built" -- outside strike's
  build-and-attest mission. If digest-preserving re-homing is ever wanted, it
  is a separate, explicitly-scoped capability with its own "copied, not built"
  attestation semantics.
- `DeploySpec.source.gitImage` is removed: dead schema, no consumer.
- The attestation target identity (the deploy target value type) is retained.
  It carries the identifier that pairs pre/post state across consecutive
  deploys to the same target (ADR-016); it is not the transport destination.
- The push destination is a mutable push reference (host, optional port, and
  repository name with a tag), not a digest-pinned reference: the digest is
  the result of the push, bound afterward in the attestation. strike validates
  it before it reaches remote.Write. The exact validation surface is settled
  with the schema change.
- The step-level provenance declaration is relocated out of the deploy region
  of the schema; it is a step concern, not a deploy concern.

### D7 -- The capture set is unified: one mechanism, method-specific content

State-recording captures (ADR-016) are the single mechanism for effect
evidence, bound to the subject as a referrer (D2). Their content varies by
method: empty for registry (the log is the chain), pre/post cluster state for
kubernetes, and the remote post-state report for the transport family. No
method carries a bespoke second recording path.

## Consequences

- Removals: the lane-wide registry field; the engine push method on the
  engine interface and its control-plane caller; the push-tag helper and the
  push-and-report step path; the registry deploy source field; the
  registry-to-registry promote; the dead git-image source; the custom deploy
  method and its type.
- Moves: SBOM cataloging from the pack step to the deploy path.
- Rewires: kubernetes manifests from stdin to `artifacts`; the registry deploy
  subject from a string source to the resolved `artifacts` image; the deploy
  push from the engine to control-plane remote.Write.
- Relocation: the provenance declaration leaves the deploy region.
- build and pack become symmetric producers: content-addressed images, no
  self-signature, no self-SBOM.
- The break is a lane-schema break (fields removed, one method removed,
  kubernetes payload source changed). Pre-beta, no migration; existing lanes
  restate deploy steps against the new shape.
- The transport family is named but unbuilt; a lane that needs a non-registry,
  non-kubernetes remote delivery waits on the ADR-038 deploy front.

## Alternatives considered

- **Generate the SBOM in the pack step.** Rejected: a build-produced published
  image would carry no SBOM without a no-op pack step, and SBOMs would be
  produced for unpublished intermediates against ADR-043's intent.
- **Make the deployed image itself the subject and bake the capture report
  into it.** Rejected: the payload is immutable and predates the capture, so it
  cannot contain a report about its own deployment without mutating the
  deployed digest; and ADR-019 is a referrer model, not a bundle model. The
  registry subject is the pushed image with the report attached as a referrer.
- **Capture the target registry inventory as a versioning chain.** Rejected:
  the transparency log plus the target identity already is that chain, from a
  stronger source; a pre-push inventory read is race-prone, adds a trusted
  peer and a failure mode, and does not catch a third-party overwrite (which a
  verifier-side log check catches instead).
- **Keep custom as an explicitly Layer-E method.** Rejected: it breaks the D2
  uniformity (one method that cannot produce a signed, SBOM'd payload subject)
  and carries the opacity the design exists to remove.

## Principles

- **Runtime is attested.** Deploy seals what the control plane holds and
  pushes; what is attested is what is delivered, by construction.
- **External references are digest-pinned.** The payload enters the deploy by
  digest; the push destination is the one mutable reference, and the signed
  subject is the resulting registry digest.
- **Reproducibility is enforced, not hoped for.** Reproducibility lives in the
  pack payload; the deploy-time SBOM inherits it over a reproducible subject.
- **Identity is asymmetric.** The observed transport identity (Layer V) and
  the step attribution (Layer E) stay unmixed in the deploy record.
- **Enforcement is structural.** The engine cannot push; a deploy cannot
  attest a payload it did not control; custom's opacity is removed rather than
  documented around.
- **Code is liability.** A lane-wide registry field, a redundant source, a
  promote path, a dead field, and an out-of-V method are removed, not carried.
