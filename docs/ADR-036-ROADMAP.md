# ADR-036 Implementation Roadmap

## Status: PARTIALLY IMPLEMENTED

## What has landed

- **Inside-workdir seed delivery (path 3).** `SeedTarFromImage()` in
  `internal/registry/seedtar.go`, `ContainerRunHeld()` with `[]ContainerSeed`
  in `internal/container/engine.go`, `buildInputSeeds` wiring in
  `cmd/strike/run.go`. Inside-workdir inputs are delivered by seeding the
  workdir named volume before container start.
- **Single-file seed naming fix.** Single-file selection emits one entry
  named `destPrefix`, not `destPrefix/basename` (commit `ca28047`).
- **Pull-once optimization.** Each producer image exported at most once per
  `buildInputSeeds` call (commit `704b9db`).
- **ADR-034 containment at admission.** Symlink containment enforced in
  `collectSeedEntries()` via `lane.SymlinkEscapes()`.
- **Single-file outside-workdir rejection.** Fail-closed with strike's own
  diagnostic before the engine sees the OCI runtime error.

## What is NOT yet implemented

### 1. Outside-workdir read-only image mount (ADR-036 path 1)

The primary open item. An input mounted outside the workdir should be
delivered as a read-only `image_volumes` entry referencing the producer's
image tag with the engine `SubPath` carrying the resolved subpath. Currently
**fail-closed** in `buildInputSeeds`.

Concrete work (from `HANDOVER_OUTSIDE_WORKDIR_MOUNT_PLANNING.md`):

- Add `specImageVolume{Source, Destination, ReadWrite, SubPath}` to the
  typed `specGen` in `internal/container/podman.go`.
- Add an `ImageVolumes` field to `executor.Run` / `RunOpts`.
- Restructure `buildInputSeeds` to return `(seeds, mounts)` -- inside-workdir
  inputs become seeds, outside-workdir inputs become image-volume mounts.
- Implement producer-layer validation for the mount path: inspect the
  producer layer to confirm the subpath is a directory and enforce ADR-034
  containment, then mount (no content walk at delivery, but validation
  requires an export+walk before mount).
- Retire the fail-closed branch for outside-workdir and workdir-less inputs.

### 2. No-workdir consumer subsumption

Steps with inputs but no workdir (test/lint steps) are currently fail-closed.
Their inputs are by nature outside any workdir and should be served via
read-only image mounts. Folds into the outside-workdir mount work.

## Sequencing

Instruction numbering continues from 54 per the handover. The outside-workdir
mount strand is the immediate next work item on the input-delivery front.

## References

- `HANDOVER_OUTSIDE_WORKDIR_MOUNT_PLANNING.md` -- planning handover
- `docs/ADR-036-engine-native-input-delivery.md` -- governing contract
- `docs/ADR-035-build-payload-in-engine.md` -- predecessor (fully implemented)
