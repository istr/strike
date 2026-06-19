# ADR-036: Engine-native step input delivery

## Status

Accepted. Sharpens [ADR-035](ADR-035-build-payload-in-engine.md) on the input
side -- the follow-up ADR-035 named when it removed host scratch from the
output side -- and sharpens [ADR-027](ADR-027-input-subpath-selection.md) on
single-file granularity. Builds on [ADR-001](ADR-001-engine-via-api-not-exec.md)
(engine via API), applies [ADR-034](ADR-034-symlink-containment.md) containment
to admission, and rests on the read-only root of
[ADR-005](ADR-005-hardened-container-profile-non-configurable.md). No schema
change and no new attestation field: the mount mechanism is not part of the
attested step spec, and inputs remain referenced by their producer image tag.

> **Amended by [ADR-046](ADR-046-one-canonical-digest-pinned-image.md):**
> inputs are referenced by their producer image's manifest digest, not its tag.
> The consumer resolves the producer step image's manifest digest and pulls or
> mounts by `repo@sha256:<digest>`; the tag is a cache-existence key only. This
> extends ADR-045's execute-by-digest rule to the input side.

> Implementation status: both delivery paths have landed. The Consequences
> below describe the seed path and the read-only image-mount path as
> "separate, sequenced strands" and "implemented as separate strands" --
> those strands are now complete (see docs/ADR-036-ROADMAP.md). The
> decision text is unchanged; only this status note is added.

## Context

ADR-035 corrected the output side: build payload stays in the engine, outputs
are projections of a workdir named volume extracted through the engine archive
API. It left the input side as an explicit follow-up -- producer artifacts
were still extracted to a host scratch directory and bind-mounted read-only,
so input payload still transited the controller host.

ADR-035 also assumed, in passing, that read-only inputs could be *mounted*
inside the workdir. A live GO/NO-GO probe against rootless Podman 5.4.2
established what the libpod REST API actually supports and refuted that
assumption in two ways:

- A read-only `image_volumes` mount works and is directory-granular. A
  `SubPath` that resolves to a single regular file is rejected by the OCI
  runtime at container start (the overlay lowerdir cannot be a file):
  create returns 201, start returns 500 with an `invalid argument: OCI
  runtime error`.
- A writable `image_volumes` overlay is writable under the hardened profile,
  but its content is not extractable after the container stops: the archive
  endpoint on a stopped container returns only the bare mountpoint directory,
  neither the written upper nor the image lower. An overlay therefore cannot
  serve as the workdir, whose whole purpose is to be archived after exit.

This ADR records the corrected input-delivery contract that follows from
those facts.

## Decision

Step inputs are delivered engine-native; producer payload no longer transits
the controller host. Two delivery paths exist, selected by whether the input
mount lies outside or inside the workdir -- the same distinction ADR-035
already uses for capturability.

1. **Outside the workdir: read-only image mount.** A read-only input mounted
   outside the workdir is delivered by an `image_volumes` entry referencing
   the producer's image tag directly, with the engine `SubPath` carrying the
   selected subpath. The producer image is already present in the engine
   store at consume time; no host extraction occurs. Such inputs serve the
   build only and are not capturable, exactly as under ADR-035.

2. **Single-file granularity narrows.** Because the read-only overlay is
   directory-granular, an input whose resolved content is a single regular
   file cannot be mounted outside the workdir. strike rejects this at
   admission with its own diagnostic, before the engine sees it: statically
   when the producing output is `type: file`, and at the admission walk when
   a subpath into a directory or image output resolves to a regular file. The
   opaque OCI runtime error is never surfaced to the lane author. Single-file
   delivery is supported only inside the workdir (path 3). An author who
   needs a single file outside the workdir mounts its parent directory and
   adjusts the consumer's arguments or workdir, or uses a directory output.

3. **Inside the workdir: seed before start.** An input mounted inside the
   workdir is delivered by seeding its resolved content into the workdir
   named volume before the container starts, via the engine archive endpoint
   on a created-but-not-started container. The seed copies; it never hands
   the step a writable handle to the stored producer artifact, so input
   immutability holds. The seeded content becomes part of the workdir tree
   and may be captured within an output projection, which is what ADR-035
   already permits for inputs inside the workdir. The workdir remains a named
   volume. This path delivers single files, because the seed is an archive
   write of a tar, not an overlay mount. It is a convenience for build tools
   that assume a writable source tree (for example, a package manifest beside
   a generated dependency directory); a workspace symlink whose ends both lie
   under the workdir stays contained.

4. **Containment is enforced at admission, in memory.** The structural
   containment ADR-034 enforces on the consume side is preserved. It moves
   from a host-directory walk to an in-memory walk over the producer content,
   keyed by the resolved subpath, run regardless of which delivery path
   applies. The walk also reports a missing subpath with strike's own
   diagnostic and is where the single-file narrowing of point 2 is detected.
   The producer-output layer convention is resolved in the caller, not at the
   engine boundary; the engine receives a fully resolved path and no knowledge
   of output types.

5. **A writable overlay is not a workdir.** A writable `image_volumes`
   overlay is not used as the workdir or as any captured surface, because its
   content is not extractable after stop. The single writable surface remains
   the named volume.

## Consequences

- The named input follow-up of ADR-035 closes for the outside-workdir path;
  input payload no longer transits the host there. The inside-workdir seed
  path and its new engine primitives are a separate, sequenced strand.
- Single-file inputs outside the workdir are a behavioral narrowing from the
  previous host-bind path. Breaking; acceptable pre-beta; no migration.
- The read-only image-mount path is retained deliberately even though the
  seed path could subsume some of it. It carries a tighter trust posture --
  the input is immutable and never enters the writable surface -- and it
  keeps a sharper build-then-test workflow possible (build read-only, test
  the artifact as a pinned input in a separate sandbox). It may be revisited
  later but is not collapsed into the seed now.
- The engine interface gains, for the seed path only, an archive-write
  primitive and a create-seed-start split. The read-only path needs only the
  typed `image_volumes` field on the request. The two are implemented as
  separate strands.
- The `image_volumes` mount carries no `noexec`/`nosuid`; the hardened
  profile (all capabilities dropped, no-new-privileges, read-only root)
  covers it, consistent with ADR-035's finding that execution-surface flags
  are not the assurance boundary.
- Attestation and the spec hash are unchanged: the mount mechanism is not in
  the hash, and the producer digest remains the trust anchor.

## Alternatives considered

- **Writable image-volume overlay as the workdir.** Rejected: overlay content
  is not extractable after stop (probed), so the output projection would be
  empty, and it would abandon the named-volume workdir ADR-035 established.
- **Read-only mount outside the workdir plus a strike-created symlink into
  the workdir.** Rejected: the surviving symlink points outside the output
  root and ADR-034 output containment rejects it; ADR-034 already rejected
  dereference-at-capture, so there is no escape.
- **Keep host extraction for single-file inputs.** Rejected: it reintroduces
  host payload transit, the exact contamination ADR-035 removes.

## Principles

- **Containers are the only storage.** Inputs are delivered engine-native --
  mounted by producer image tag or seeded from it -- so producer payload no
  longer transits the controller host.
- **External references are digest-pinned.** Every input is referenced by its
  producer image tag, which is content-addressed by spec hash; no mutable
  handle is introduced.
- **Reproducibility is enforced, not hoped for.** The seed writes a
  canonical tar deterministically, and admission containment is decided
  lexically and identically with the produce side.
- **Code is liability.** The read-only path adds a typed request field, not a
  new mechanism; one lexical containment routine serves admission for both
  delivery paths.
- **Enforcement is structural, not discretionary.** Containment runs at
  admission per mount with no opt-out, and the single-file narrowing fails
  closed with a strike diagnostic rather than deferring to an opaque engine
  error.
