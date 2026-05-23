# ADR-035: Build payload stays in the engine; outputs are workdir-volume projections

## Status

Accepted. Sharpens [ADR-026](ADR-026-containers-as-sole-inter-step-storage.md)
(containers are the only storage) by correcting a misimplementation. Builds
on [ADR-005](ADR-005-hardened-container-profile-non-configurable.md)
(read-only root), [ADR-001](ADR-001-engine-via-api-not-exec.md) (engine via
API), and applies [ADR-034](ADR-034-symlink-containment.md) containment to
extraction. Makes one minimal, clarifying schema change
([ADR-004](ADR-004-cue-as-single-source-of-truth.md)): `#OutputSpec.path`
becomes `#RelPath`, relative to the `#AbsPath` workdir. Output identity and
attestation need no new fields; they rest on the existing content-addressed
artifact model ([ADR-008](ADR-008-cryptographic-primitives.md),
[ADR-012](ADR-012-engine-identity-capture.md),
[ADR-013](ADR-013-dsse-envelope-and-rekor.md)).

## Context

The implementation materialized step outputs through a host scratch
directory: strike created a temp dir, mounted it at a fixed `/out`, let the
container write into it, and after the run read the outputs host-side and
wrapped subtrees by name. This conflated three roles in one host directory:
the writable build base, the output read-back channel, and the output root.

The conflation put build payload on the controller host. That violates the
true meaning of ADR-026: inter-step payload must live only in the engine
and never transit the controller's filesystem. Three observed failures
trace to this single root cause -- a directory output containing a symlink
was rejected at the host walk; a workdir below `/out` was unwritable because
the read-only input mounts materialized its parent root-owned; and an output
whose path equaled the mount root failed name resolution (`filepath.Base`
mismapping). They are not three bugs but three symptoms of one architectural
error.

Two facts settle the corrected model. First, ADR-005 makes the container
root read-only: a step cannot modify the base filesystem, so everything a
step *produces* lands in a writable mount; the only persistent writable
surface is the workdir volume (the tmpfs at `/tmp` is ephemeral scratch,
gone at stop). Second, the lane schema already declares a single optional
`workdir`. "One writable workdir" is therefore already an invariant; it only
needs its role named.

## Decision

A run step has exactly one persistent writable surface: an engine-managed
volume mounted at the workdir. The tmpfs at `/tmp` remains ephemeral scratch
and is never an output. The base filesystem is read-only.

Outputs are projections of the workdir volume. The workdir is an absolute
container path (`#AbsPath`) where the single writable volume is mounted; an
output `path` is a path relative to it (`#RelPath`). The type makes the
relativity explicit and rules out an absolute path that would silently mean
something workdir-relative; an empty or `.` output path denotes the whole
workdir (the projection at the volume root). A relative path that climbs
above the workdir via `..` is rejected by the same lexical containment as
ADR-034. An output cannot reference an arbitrary base-image path: under
read-only root the base is not something the step produced, and forwarding
unchanged base content is a copy/assembly concern (a pack step or an input
selection), where its origin stays explicit. The fixed `/out` mount target
is removed. This is the one schema change, and it is CUE-first: `#OutputSpec`
is amended before the Go types regenerate.

Read-only inputs mounted inside the workdir (with their declared, attested
provenance) are part of the workdir tree and may be captured within an
output projection. Inputs mounted outside the workdir serve the build only
and are not capturable.

After the step exits, strike holds the container (run without auto-removal,
container id returned), extracts each output projection from the container's
filesystem through the engine archive API, canonicalizes the resulting tar
in memory (zeroed mtime and ownership, stable ordering, with ADR-034 symlink
containment enforced per output root), and loads it as the output image.
The container and the workdir volume are removed only after extraction.
Build payload never touches the controller host filesystem.

There is no container commit. Under read-only root a commit captures the
empty top layer, not the volume content, so it would not contain the build
at all; and it is unnecessary. Each output is independently wrapped into a
content-addressed OCI image whose manifest digest is its identity -- already
registered in lane state, used as the image tag, and size-annotated
(`dev.strike.content-size`). That digest is the attested result anchor; the
output's source path is part of the attested step spec. No new attestation
field is required.

The workdir mount path is a usability choice with no semantic weight: the
single writable volume is the invariant, and the author places its
mountpoint to suit a tool that expects a fixed path or keeps an implicit
HOME there. The same choice satisfies the read-only-root requirement that
every tool-writable location (HOME, caches) resolve to the workdir volume or
to tmpfs.

## Consequences

- Both build conventions are served by one model. A traditional build
  (read-only sources, separate build directory) sets the workdir to the
  build directory and exports it. A modern tool that assumes a writable
  source tree sets the workdir to that tree, mounts the read-only inputs
  inside it, and exports the workdir root; a workspace symlink such as
  `node_modules/website -> ../packages/foo` is contained because both ends
  lie under the workdir.
- The three symptom failures dissolve: no host scratch, no `/out` coupling,
  no name mismapping.
- A producing run step requires a workdir (the writable volume); validated.
- The `#OutputSpec.path` type change (`#AbsPath` to `#RelPath`, relative to
  workdir) is a breaking lane-schema change; acceptable pre-beta, no
  migration. Existing lanes restate their output paths relative to the
  workdir.
- No persistent cross-run caches: a second persistent writable volume is not
  provided, and a persistent cache would undermine reproducibility. Ephemeral
  build scratch uses tmpfs.
- Extraction is engine-native (the archive API), consistent with ADR-001;
  no subprocess, no host materialization of payload.
- The engine interface changes: `ContainerRun` is split so strike can act
  between exit and removal (run without auto-removal, return the id); a
  `ContainerArchive(id, path)` reader is added; container removal becomes a
  distinct call; workdir volume create and remove are added. No commit call.
- In-memory canonicalization keeps payload off the host disk. If a very
  large layer ever requires spill-to-disk, it must be explicit and isolated,
  never the silent default, or host contamination returns through the back
  door.
- Two contamination fronts remain and are cut off as named follow-ups
  (risk-oriented sequencing; this change is large enough alone): the input
  side still extracts producer artifacts to a host scratch before bind
  mounting (engine-native image mounts are the fix, touching ADR-027 and
  ADR-034 input validation), and the registry helpers still round-trip
  through `os.MkdirTemp` when building and loading layers. The unreliable
  ephemeral-CA cleanup (deferred cleanups skipped on `log.Fatal` exit paths)
  is a separate parked issue.

## Alternatives considered

- **Export any path of the merged container filesystem** (a `docker commit`
  / loose multistage reading, "give me `/etc` from the result"). Rejected.
  Under read-only root the diffuse system production this would capture is
  impossible, so the extra power is largely unusable; what remains is
  scraping unchanged base content, which silently mixes base-image bytes
  into a step's artifact and blurs whether the step produced a path or
  inherited it. Arbitrary-path selection belongs on the consumer/assembly
  side -- input subpath selection (ADR-027) and pack steps, which is where
  multistage `COPY --from` puts it -- not in producer output.
- **Commit the container to obtain a result digest.** Rejected: a commit
  excludes volume content (the build) under read-only root and is redundant,
  since each output is already a content-addressed image.
- **Keep the host scratch and fix only the name mapping and writability.**
  Rejected: it treats the symptoms and leaves payload on the controller
  host, the actual defect.

## Principles

- **Containers are the only storage.** The corrected reading: inter-step
  payload lives only in the engine and never on the controller host, not
  even transiently through a scratch mount.
- **Enforcement is structural, not discretionary.** Read-only root makes the
  workdir volume the sole production surface; an output cannot escape it,
  and there is no opt-out that would let payload onto the host.
- **Reproducibility is enforced, not hoped for.** The engine tar is
  re-canonicalized (zeroed mtime and ownership, stable ordering) before it
  becomes a layer; the output digest is deterministic.
- **External references are digest-pinned.** Each output is a
  content-addressed image; its manifest digest is the attested result
  anchor, so no separate result record is introduced.
- **CUE first.** The output path's type is its contract: `#RelPath` states
  "relative to workdir" and forbids absolute escape, rather than overloading
  `#AbsPath` with a second, surprising meaning.
- **Code is liability.** The host-scratch read-back path and the conflated
  `/out` mapping are removed rather than patched.
