# ADR-026: Containers as Sole Inter-Step Storage Object

## Status

Accepted.

## Scope

This ADR concerns the storage layer between steps in a strike
lane execution: how a step's output reaches the next step's
input, where intermediate artifacts live, and how caching
across strike invocations is achieved.

It establishes a new design principle and operationalises it in
strike's runtime architecture. The principle text is duplicated
verbatim in `DESIGN-PRINCIPLES.md` as the new "Containers are
the only storage" entry.

## Context

The current strike implementation uses per-step scratch
directories on the host filesystem (`/tmp/strike-<step>-<random>/`)
as the inter-step storage substrate. A step writes its output
to its scratch directory; the next step bind-mounts the
producer's scratch directory as a read-only input.

This produces three structural problems:

1. **Scratch leaks past process lifetime.** Empirically observed
   in a user's `/tmp/`: scratch directories from past strike
   invocations remain on disk indefinitely. The architectural
   principle "the container registry is the only place of
   persistence" is in direct tension with the operational
   reality of strike-managed state on the host filesystem.
2. **Host filesystem is a parallel persistence layer.** Step
   outputs on the host are visible to other processes running
   under the same UID, survive strike process termination, and
   constitute storage that strike's own attestation chain
   neither references nor verifies.
3. **No caching across runs.** Re-running a lane re-executes
   every step from scratch, even when the inputs, args, image
   digest, and env are bit-identical to the previous run.
   For lanes that pull from remote sources (git+ssh, npm
   registry, large container registries), this means repeated,
   expensive network IO during normal development iteration.

Strike already has image-typed step outputs that flow through
the container engine's local image store via the existing
`image_from` reference mechanism. That mechanism content-
addresses its content via image digest, caches naturally in
the engine's local image store, and surfaces verifiable
references in the DAG. Generalising this mechanism to all step
output types eliminates the three problems above.

## Decision

Every step output, regardless of declared type
(`file`, `directory`, `image`), is encoded as an OCI container
image with a deterministic tag derived from the step's spec
hash. Strike's inter-step storage interface is the container
engine API (the libpod API, via the podman socket). The
engine's local image store is the storage and cache layer;
strike implements no separate cache mechanism.

The specific decisions:

### Storage object

Every step produces exactly one image per declared output.
The image has a single layer containing the output content:

- `file` outputs: a single-layer image whose layer contains the
  file at its declared path within the image.
- `directory` outputs: a single-layer image whose layer is a
  tarball of the directory tree at its declared path within
  the image.
- `image` outputs: the image produced by the step's pack
  operation, unchanged from current behaviour.

The image is loaded into the engine's local image store via
`POST /libpod/images/load` immediately after the step's
container exits successfully.

### Tag scheme and digest references

Loaded images are tagged
`localhost/strike/<lane_id>/<step_name>:<spec_hash>`. The
`localhost/` prefix marks the image as locally produced (not
pulled from any registry). The lane_id and step_name provide
namespacing across lanes co-existing on the same engine. The
spec_hash is the strike-defined deterministic hash over the
step's args, image digest, env, and resolved input digests.

Tags are the lookup key for cache-existence checks: strike
queries the engine by tag, the engine returns the
corresponding image (which it knows because it maintains an
internal tag-to-manifest-digest mapping). Strike does not
maintain its own mapping; the tag is the cache key, the engine
is the resolver.

A second tag form is used when pushing or pulling cache
artifacts through an external registry. The remote-cache tag
is `<registry>:<step_name>-<first16hex>`, where `<first16hex>`
is the first 16 hex characters of the step's spec hash. The
16-character truncation keeps tags within OCI registry length
conventions while preserving ample collision resistance for a
per-lane cache (16 hex = 64 bits). The function is
`internal/registry/cache.go::Tag`.

The two forms target different name systems and intentionally
differ in structure:

- Local form (`localhost/strike/<lane_id>/<step_name>:<spec_hash>`,
  produced by `registry.WrapTag`): used for the engine's local
  image store. The `localhost/` prefix marks the image as
  locally produced; the lane_id namespaces across lanes
  co-existing on one engine; the full 64-character spec hash
  tag is the cache key.
- Remote form (`<registry>:<step_name>-<first16hex>`,
  produced by `registry.Tag`): used when pushing cache
  artifacts to or pulling them from an external registry.
  The registry takes the place of `localhost/strike/<lane_id>/`
  as the namespace, and the truncated hash respects tag-length
  conventions.

Both forms ultimately resolve to the same manifest digest,
which is what attestations and inter-step DAG references
actually record. Tags are lookup keys, not cryptographic
anchors.

Tags are not the cryptographic anchor. Attestations and
inter-step DAG references record the **manifest digest** of
each step's output, resolved from the engine after the image
is loaded. The digest is the immutable identifier; the tag is
the convenience handle. An external verifier reading a strike
attestation sees image digests, not tags, and resolves those
digests through whatever engine or registry it has access to.

### Cache-skip semantics

Before executing a step, strike calls `GET /libpod/images/<tag>/json`
with the tag computed from the step's spec hash. If the
engine reports the image exists, strike skips execution
entirely: no container is created, no command is run. The
existing image is treated as the step's output.

If the engine reports 404, strike runs the step normally.

### Opt-out: `force_run`

A new optional boolean field on the step schema:
`force_run: bool` (default `false`). When `true`, strike
bypasses the existence check and runs the step unconditionally.
The output is still loaded into the engine store, replacing
any prior tag. Downstream steps cache normally on the resulting
image digest.

The field describes what strike does (run the step) rather
than the effect (cache miss). This phrasing is robust against
future implementation changes in the cache mechanism: the
semantics of "force this step to run" do not depend on how
caching works internally.

This is the explicit escape hatch for intentionally non-
deterministic steps (a `git clone` from a moving branch, an
`npm install` of a `latest` tag). Strike does not auto-detect
non-determinism; the lane author declares it explicitly.

### Input references

Step inputs reference producer outputs by their image tag. The
engine's image store is the resolution layer; strike does not
maintain its own mapping. The `image_from` pattern, currently
restricted to image-typed outputs, becomes the universal
inter-step reference mechanism.

The mount construction for an input is implementation-flexible
within these bounds:
- An ephemeral container is created from the input image
  (`POST /libpod/containers/create` with `Image: <input-tag>`).
- The container's rootfs (or specific layer paths) is mounted
  into the consuming step's container via `--mounts-from` or
  equivalent bind-mount-of-mounted-rootfs.
- The ephemeral container is removed when the consuming step
  exits.

The specific mechanism is for the implementation instruction
file, not this ADR. What matters is that strike does not
extract image contents to a host scratch directory and then
bind-mount that.

### Cross-machine persistence

Pushing step outputs to an OCI registry is an **explicit,
optional** operation, not part of the default storage path.
Strike provides:

- A per-step `publish: <registry>` field (or equivalent;
  exact schema deferred to the implementation instruction
  file). When set, strike calls
  `POST /libpod/images/<tag>/push` against the named registry
  after the step's image is loaded into the local store.
- The publish field is independent of the storage path; strike
  always loads locally first, then optionally pushes.

Cross-machine cache sharing (engine A produced an image,
engine B needs it) requires an operator-configured registry
and explicit publish on the producing side. The pulling side
references the registry-qualified tag.

### Per-step scratch lifetime

The per-step scratch directory on the host is created at step
start and removed via `defer os.RemoveAll(scratchDir)` on
step exit. The deferred call fires on normal step exit
(success or failure), on panics with recover, and on
gracefully-handled termination signals (context cancellation).

In the residual case of `SIGKILL` or hardware-level
termination, a scratch directory persists until manual cleanup
or system reboot. This residual leaves no state strike needs
to recover: the engine's image store either contains the
step's loaded output (step completed and load succeeded) or it
does not (step was interrupted before load). There is no
intermediate state to reconcile.

Container engine image loads happen from the scratch
directory: strike packages the output into a tar, calls
`images/load`, the engine ingests the layers, scratch
disappears. The same scratch directory holds the SSH-related
configuration files (per ADRs 024 and 025), which similarly
disappear when the step ends.

## Principles

This ADR adds a new design principle:

> **Containers are the only storage.** Strike does not
> implement a cache, a state directory, or a host-side
> intermediate filesystem. Every artifact that survives a
> step boundary is an OCI container image. The container
> engine's local image store is the storage and cache layer;
> an OCI registry provides optional cross-machine and
> long-term persistence. Strike's storage interface is the
> container engine API; registry interaction is an explicit
> operation, not the default storage path.

It also reinforces existing principles:

- **External references are digest-pinned** -- generalised:
  every inter-step reference is an image digest reachable
  through the engine's image store. Mutable references
  (`:latest`, branch names) are an opt-in non-determinism
  surfaced via `force_run`, not a silent quality compromise.
- **Code is liability** -- removes strike's own cache layer
  entirely; the engine's image store replaces it.
- **Reproducibility is enforced** -- bit-identical inputs
  produce bit-identical outputs that produce bit-identical
  image digests, the cache key.

## What is explicitly excluded

These are structural exclusions, not deferred items.

- **A strike-internal cache directory or cache database.**
  No `~/.cache/strike/`, no SQLite, no on-disk index. The
  engine's image store is the cache.
- **File or directory outputs as raw filesystem state crossing
  step boundaries.** The lane-author-facing types remain
  `file`, `directory`, `image`; storage-internally they all
  collapse to images. There is no fast path that skips the
  image wrapping for "small" outputs.
- **An embedded registry server inside strike.** Strike does
  not host an OCI Distribution endpoint. Cross-machine sharing
  uses an external registry (operator-run).
- **OCI Distribution as the default storage path.** Local
  storage is via the engine API; registry is opt-in for
  cross-machine and persistence.
- **Strike-managed cache invalidation logic.** Content
  addressing makes invalidation trivial: a different spec hash
  is a different image. There is nothing to invalidate.
- **Persistence of half-finished step outputs.** A step that
  fails or is interrupted leaves nothing in the image store.
  The producer-step contract is: image appears on successful
  exit, or not at all.

## What is deferred

These are open architectural questions for future ADRs, not
exclusions.

- **Docker-compat API migration.** Strike currently uses
  libpod-specific endpoints. Whether to migrate to Docker-compat
  endpoints is a separate question that may be addressed in a
  future ADR if it becomes relevant. This ADR makes no
  commitment in either direction.
- **Engine-store GC policy.** Operators control image
  retention via their engine configuration (`podman system
  prune`, etc.). Strike does not manage GC; a cache miss after
  GC simply re-runs the step.
- **Subpath selection on inputs** so a step can mount one
  file from a multi-file producer image without an
  intermediate extract step. Own ADR (resolved by ADR-027).
- **Multi-machine cache federation** beyond the basic push/pull
  pattern (e.g., pull-through caches, content-trust
  delegation). Own ADR when a concrete case appears.
- **Image-store quota or backpressure.** Strike does not bound
  the engine's image-store growth.

## Consequences

- The `/tmp/strike-*` leak class becomes structurally
  impossible. Per-step scratch is bounded to a single step's
  lifetime by construction.
- Caching across strike invocations is automatic. A repeated
  run of an unchanged lane completes in the time of the
  cache-existence checks plus any genuinely changed steps.
- A single local service (the engine socket) is the only
  service required for development. The setup the operator
  already runs -- `podman system service --time=0
  unix:///run/user/<uid>/podman.sock` -- is sufficient.
- Cross-machine sharing requires an explicit operator decision
  (configure a registry, set `publish` on relevant steps).
  This is by design: cross-machine sharing has trust and
  governance implications that should not be silent defaults.
- Small artifacts pay container-wrapping overhead (manifest +
  config + layer for a tiny file). Acceptable in exchange for
  uniform storage, uniform tooling, uniform tooling.
- Build introspection becomes standard: `podman images`,
  `podman image inspect`, and `podman image tree` show
  strike's intermediate state directly.
- External verification of strike attestations remains intact:
  attestations reference image digests; the verifier resolves
  digests through whatever engine or registry it has access
  to. Strike's verifier story is unchanged in shape.
- The `image_from` pattern, currently a single output-type's
  feature, becomes the universal mechanism. The codebase
  simplifies: one input-resolution path, not three.
- Lane authors gain the `force_run` flag for intentional non-
  determinism. Lane authors lose nothing: `file` and
  `directory` output types remain in the schema; their storage
  representation changes invisibly.

## Implementation note

The migration is staged across a sequence of PRs, not a single
landing. Concretely:

1. Foundation: file/directory output wrapping into images
   exists alongside the existing scratch path. Both paths run.
2. Switch outputs: producer steps store via images/load
   exclusively. Consumer steps still bind-mount from scratch.
3. Switch inputs: consumer steps reference producer images
   exclusively. Bind-mount-from-host-scratch is removed.
4. Cache-skip: existence check via engine API. `force_run`
   honoured.
5. Cleanup: dead code removed, principle added to
   DESIGN-PRINCIPLES.md.

Each stage is independently testable and reverts cleanly. The
instruction files for each stage are separate from this ADR.
