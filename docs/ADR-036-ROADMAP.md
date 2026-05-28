# ADR-036 Implementation Roadmap

## Status: IMPLEMENTED

## What has landed

- **Inside-workdir seed delivery (path 3).** `SeedTarFromImage()` in
  `internal/registry/seedtar.go`, `ContainerRunHeld()` with `[]Seed`
  in `internal/container/engine.go`, `buildInputDelivery` wiring in
  `cmd/strike/run.go`. Inside-workdir inputs are delivered by seeding the
  workdir named volume before container start.
- **Single-file seed naming fix.** Single-file selection emits one entry
  named `destPrefix`, not `destPrefix/basename` (commit `ca28047`).
- **Pull-once optimization.** Each producer image exported at most once per
  `buildInputDelivery` call (commit `704b9db`); the shared producer-export
  cache covers both seed and mount delivery paths.
- **ADR-034 containment at admission.** Symlink containment enforced in
  `collectSeedEntries()` via `lane.SymlinkEscapes()`.
- **Single-file outside-workdir rejection.** Rejected with strike's own
  lane-surface diagnostic before the engine sees the OCI runtime error,
  statically when the producing output is `type: file` and at the validation
  walk when a subpath resolves to a regular file.
- **Outside-workdir read-only image mount (path 1).** Inputs mounted
  outside the workdir, and every input on a step with no workdir, are
  delivered as read-only `image_volumes` entries referencing the producer
  image tag, with the engine `SubPath` carrying the resolved subpath.
  `container.ImageVolume` + `specImageVolume` (the typed `specGen` field),
  `RunOpts.ImageVolumes` threaded through `executor.Run`, and the
  `buildInputDelivery` classifier returning `(seeds, mounts)`. Producer
  layers are validated before mount by `registry.ValidateImageMount`
  (directory-or-file kind + ADR-034 containment), sharing one walk kernel
  with the seed path. Confirmed end to end against rootless podman.
- **No-workdir consumer.** A step with inputs but no workdir is served by
  read-only image mounts; the previously fail-closed branch is retired.
  The no-workdir path reaches the executor with mounts and no writable
  volume.

## Sequencing

The outside-workdir mount strand landed across four instructions (the
image-volume engine primitive, the shared producer-layer walker plus
image-mount validator, the input-delivery split, and this integration
and closure). The input-delivery front of ADR-036 is complete.

## References

- `HANDOVER_OUTSIDE_WORKDIR_MOUNT_PLANNING.md` -- planning handover
- `docs/ADR-036-engine-native-input-delivery.md` -- governing contract
- `docs/ADR-035-build-payload-in-engine.md` -- predecessor (fully implemented)
