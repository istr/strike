# Contributing to strike

Thank you for considering a contribution. This document explains the project's
goals and what we are (and are not) looking for.

## Project goals

strike exists because existing CI/CD tools have become unnecessarily complex.
Tools like act, dagger, and concourse each bring their own engine containers,
daemon processes, custom runtimes, or embedded scripting layers. They solve
real problems, but they do so with a footprint that is difficult to audit,
expensive to maintain, and hostile to reproducibility.

strike takes a different approach:

- **Small footprint.** The entire executor is a single static binary, a few
  hundred lines of Go. The lane schema is defined in CUE. There is no
  daemon, no database, no sidecar. We actively resist growth in lines of code
  and will push back on contributions that add complexity without clear
  justification.

- **No shell.** Lanes are flat. They do not use shell interpreters. Steps are an image
  reference and an args array. There are no `run:` blocks, no `bash -c`, no
  string interpolation, no template engines. This is a core invariant, not a
  missing feature.

- **Rootless container engine.** strike runs entirely under rootless podman.
  No privileged containers, no Docker socket, no DinD. Every step runs with
  digest-pinned images and network disabled by default (`--network=none`).
  Steps that need outbound access must explicitly opt in with `network: true`.

- **Reproducible builds.** The bootstrap process proves reproducibility: the
  tool builds itself twice and compares the output. Cache keys are derived from
  a Merkle tree over image digests, arguments, and source hashes -- not
  timestamps, not build IDs, not mutable tags.

## What we welcome

**Bug fixes** -- always welcome. If something is broken, please open an issue
or send a merge request with a clear description of the problem.

**Improvements** -- if they reduce complexity, improve correctness, or make the
codebase smaller. Refactoring that removes code is valued more than refactoring
that adds abstractions.

**Features aligned with the project goals** -- new capabilities that maintain
the small footprint and no-shell invariant.

**Support for other rootless container engines** -- this is highly welcome.
strike currently targets podman, but the executor interface is deliberately
thin. Contributions that add support for other rootless runtimes are a natural
fit. In particular, a path toward unikernel-based execution via
[Unikraft](https://unikraft.org/) / [KraftKit](https://github.com/unikraft/kraftkit)
would be appreciated. If you are working in that space, please open an issue to
discuss the approach.

## What we will not accept

**Shell execution.** No `sh -c`, no embedded scripts, no template expansion
in lane definitions. This is the line we will not cross.

**Secondary state.** strike does not maintain state beyond what is in the
container store and the OCI registry. No local databases, no lock files, no
run history, no build logs persisted to disk. The registry is the single source
of truth for cached artifacts.

**Cache optimization to reduce registry traffic.** The caching model is
content-addressed and registry-backed by design. We will not add local cache
layers, deduplication heuristics, or "smart" prefetching to save registry
round-trips. If registry cost is a concern, use a pull-through cache at the
infrastructure level -- that is not strike's problem to solve.

**Large dependencies or engine containers.** strike is a static binary that
shells out to podman. We will not embed container runtimes, add gRPC services,
bundle web UIs, or introduce daemon processes.

## How to contribute

1. Fork the repository.
2. Create a branch from `main`.
3. Make your changes. Keep diffs small and focused.
4. Run `go vet ./...` to verify the build.
5. Open a merge request with a clear description of what and why.

For larger changes, please open an issue first to discuss the approach. This
saves time for everyone.

## Code style

- English for all comments, error messages, and documentation.
- ASCII only in source files.
- No unnecessary abstractions. Three similar lines are better than a premature
  helper function.
- If you add a feature, it should work without shell. If you cannot express it
  without shell, it is out of scope.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
