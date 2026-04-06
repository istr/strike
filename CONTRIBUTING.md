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
  thousand lines of Go. The lane schema is defined in CUE. There is no
  daemon, no database, no sidecar. We actively resist growth in lines of code
  and will push back on contributions that add complexity without clear
  justification.

- **No shell.** Lanes are flat. They do not use shell interpreters. Steps are an
  image reference and an args array. There are no `run:` blocks, no `bash -c`,
  no string interpolation, no template engines. This is a core invariant, not a
  missing feature.

- **Rootless container engine.** strike runs entirely under rootless podman.
  No privileged containers, no Docker socket, no DinD. Every step runs with
  digest-pinned images and network disabled by default (`--network=none`).
  Steps that need outbound access must explicitly opt in with `network: true`.

- **Reproducible builds.** The bootstrap process proves reproducibility: the
  tool builds itself twice and compares the output. Cache keys are derived from
  a Merkle tree over image digests, arguments, and source hashes -- not
  timestamps, not build IDs, not mutable tags.

- **Schema-driven data model.** Every data structure that crosses a package
  boundary is defined in CUE under `specs/`. CUE schemas are the single
  source of truth -- Go types are either generated from CUE or validated
  against CUE at runtime. This ensures every implementation (Go, Rust
  verifier, external policy engines) works against the same contract.

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
communicates with the container engine via REST API over Unix socket. We will
not embed container runtimes, add gRPC services, bundle web UIs, or introduce
daemon processes.

**Untyped cross-package data.** Do not introduce `map[string]string` or
`interface{}` for structured data that flows between packages. If your feature
needs new data to cross a boundary, define it in a CUE schema first, get it
approved, then implement the Go types.

## How to contribute

1. Fork the repository.
2. Create a branch from `main`.
3. **If your change introduces or modifies data structures that cross
   package boundaries, start with the CUE schema.** Add or update types
   in `specs/*.cue`, run `make specs` to validate, then open an issue or
   draft MR to discuss the schema before writing Go code. Schema changes
   are architectural decisions and will be reviewed carefully.
4. Make your changes. Keep diffs small and focused.
5. Ensure all quality gates pass (see below).
6. Open a merge request with a clear description of what and why.

For larger changes, please open an issue first to discuss the approach. This
saves time for everyone.

## Quality gates

Every merge request must pass these checks. CI enforces them; save yourself
the round-trip by running them locally first.

### Lint and static analysis

```sh
golangci-lint run ./...
```

The project uses a strict `.golangci.yml` configuration that includes gosec for
security scanning. All findings must be resolved -- do not add `//nolint`
without a written justification in a code comment explaining why the finding is
a false positive.

### Tests

```sh
go test -race -coverprofile=coverage.out -covermode=atomic ./...
```

Requirements:

- All new code must have unit tests.
- All new tests must use table-driven subtests with `t.Run`.
- Tests must pass with the race detector enabled.
- Coverage must not decrease. Target: 100% statement coverage for all packages
  except generated code (`cue_types_lane_gen.go`).
- Container operations are tested via `httptest` mock servers against the
  `container.Engine` interface. Unit tests must not require podman.

### Vulnerability scan

```sh
govulncheck ./...
```

Zero findings required. If a dependency has a known vulnerability in code paths
strike actually calls, either upgrade the dependency or remove it.

### Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike
```

The binary must build as a static, pure-Go executable.

## Code style

The complete style guide is in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). The
essential rules:

- English for all comments, error messages, and documentation.
- ASCII only in source files.
- No unnecessary abstractions. Three similar lines are better than a premature
  helper function.
- If you add a feature, it must work without shell. If you cannot express it
  without shell, it is out of scope.
- Error strings: lowercase, no trailing punctuation, no "failed to" prefix.
  Use `fmt.Errorf("signing image %s: %w", ref, err)`.
- Doc comments on all exported names. Start with the name of the element.
- No `os/exec.Command("sh", "-c", ...)` anywhere. This is a security invariant.
- All container operations go through the `container.Engine` interface (REST API
  over Unix socket).
- Path operations on untrusted input must use `filepath.IsLocal` and
  prefix validation.
- Secrets must never appear in error messages, logs, or process arguments.
- Data structures crossing package boundaries must be defined in CUE schemas
  under `specs/` before Go implementation. No `map[string]string` for
  structured inter-package data.

## Security review

Changes touching these areas require extra scrutiny:

- `specs/*.cue` -- CUE schema changes affect the cross-implementation
  contract and every existing attestation in every registry
- `internal/executor/` -- container security profile, signing, SBOM generation
- `internal/registry/` -- OCI registry interaction, cache integrity
- `internal/deploy/` -- command execution, state capture
- `cmd/strike/main.go` -- secret handling, digest verification

If your change modifies how external commands are invoked, how paths are
constructed from user input, how secrets flow through the system, or how
cryptographic operations are performed, call this out explicitly in the merge
request description.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
