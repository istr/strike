# AGENTS.md -- Instructions for AI Coding Agents

This file contains instructions for Claude Code, Copilot, and similar AI
coding agents working on the strike codebase. Read this entire file before
making any changes.

## Project overview

strike is a rootless, shell-free, container-native CI/CD executor written in
Go. It is a single static binary (~16 MB) that invokes podman to run build
steps in hardened containers. The codebase is intentionally small (~4000 lines)
and must stay small. Every line of code is a liability.

Module path: `github.com/istr/strike`
Go version: 1.26+
Build: `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike`

## Hard invariants -- never violate these

1. **No subprocess execution.** Never use `exec.Command`, `exec.CommandContext`,
   `os/exec`, or any subprocess spawning anywhere. All external operations --
   container execution, state capture, kubectl, HTTP probes -- use the
   `container.Engine` REST API over Unix socket. There are zero `os/exec`
   imports in the codebase. This is a security invariant, not a style
   preference.

2. **No new dependencies without justification.** The project has ~28
   transitive dependencies. Do not add dependencies. If you need functionality
   from a library, copy the relevant code (with attribution) or implement it.
   "A little copying is better than a little dependency."

3. **No daemon processes, no embedded servers, no gRPC, no web UI.** strike is
   a CLI tool that runs and exits.

4. **Secrets never appear in logs, error messages, or process arguments.**
   Secret values are held in memory and passed via environment variables only.

5. **All external images must be digest-pinned.** References like
   `image:latest` or `image:v1.0` are rejected. Only `image@sha256:...` is
   accepted for external registry images.

6. **Unsigned OCI images must not be used by network-enabled steps.** This
   guard prevents exfiltration of tampered images.

7. **TCP connections require TLS.** Unencrypted TCP to the container
   engine is rejected at startup. Server-side TLS (TLS 1.3 minimum) is
   mandatory. Set `CONTAINER_TLS_CA` to pin a specific CA, or omit it to
   use the system CA store. Set `CONTAINER_TLS_CERT` and
   `CONTAINER_TLS_KEY` for optional mutual TLS. Unix socket connections
   are not affected.

## Package structure

```
cmd/strike/main.go   CLI entry, dependency wiring, lane execution orchestration
internal/
  container/         Container engine REST API client (Engine interface, podman impl)
  lane/              Pipeline definitions, CUE schema, DAG, state, digests
  executor/          Container execution, OCI pack, signing, SBOM
  registry/          OCI registry operations, caching, spec hashing
  deploy/            Deployment with mandatory state attestation
```

Do not create new packages under internal/ without discussion. Do not create
`pkg/`, `util/`, `common/`, `helper/`, `models/`, `types/`, or `interfaces/`
packages.

### Key files

- `specs/lane.cue` -- CUE schema for lane definitions (source of truth).
  `specs/attestation.cue` -- CUE schema for deploy attestations.
  After editing, run `make generate` to re-export JSON Schema and
  regenerate `internal/lane/cue_types_lane_gen.go`. Never edit the
  generated file by hand.
- `internal/container/engine.go` -- Engine interface and types. All container
  operations go through this interface.
- `internal/container/podman.go` -- Podman libpod REST API implementation.
- `internal/executor/sign.go` -- ECDSA P-256 signing. Uses `crypto/rand`, never
  `math/rand`.
- `cmd/strike/main.go` -- Orchestrates lane execution. Long but intentionally
  procedural. Do not abstract it into a framework.

## Security rules

### Container operations

All operations use the `container.Engine` interface, which communicates
via REST API over Unix socket. There are zero `exec.Command` calls and
zero `os/exec` imports in the entire codebase. State capture commands,
kubectl operations, and HTTP probes all run inside containers via the
Engine API.

```go
// CORRECT -- use the Engine interface
exitCode, err := engine.ContainerRun(ctx, container.RunOpts{
    Image: "image@sha256:...",
    Cmd:   []string{"build"},
})

// PROHIBITED -- exec.Command, exec.CommandContext, os/exec
cmd := exec.Command("podman", "run", imageRef)   // NEVER
cmd := exec.CommandContext(ctx, "curl", url)      // NEVER
```

### Path handling

All file path operations involving untrusted input (image contents, tar
entries, lane-defined paths) must:
- Validate with `filepath.IsLocal()` (Go 1.20+) before use.
- Verify the resolved path stays within the intended directory.
- Never trust `filepath.Clean()` alone as a security control.

```go
// CORRECT -- validate tar entry paths
if !filepath.IsLocal(header.Name) {
    return fmt.Errorf("path traversal in tar entry: %q", header.Name)
}

// WRONG -- filepath.Clean does not prevent traversal
clean := filepath.Clean(header.Name)
```

### Tar extraction

When reading tar archives (OCI layers, cache artifacts):
- Reject entries with `..` path components.
- Reject symlinks pointing outside the extraction directory.
- Enforce maximum file size with `io.LimitReader` (prevent decompression bombs).
- Validate entry types (reject device nodes, FIFOs, etc.).

### Error messages

Error messages must not contain:
- Secret values, passwords, or tokens.
- Full file system paths from the host (use relative paths).
- Internal IP addresses or hostnames.
- Stack traces (unless debug mode is explicitly enabled).

Error strings must be lowercase, without trailing punctuation:

```go
// CORRECT
return fmt.Errorf("signing image %s: %w", ref, err)

// WRONG
return fmt.Errorf("Failed to sign image: %s. Error: %v", ref, err)
```

### Reproducible builds

Pack steps produce deterministic OCI images. All timestamps use
`SOURCE_DATE_EPOCH` (per https://reproducible-builds.org/specs/) when
set, otherwise Unix epoch 0. Never use `time.Now()` in any code path
that affects image content, SBOM data, or attestation payloads.

### Cryptography

- Use `crypto/rand` for all random number generation. Never `math/rand`.
- Use `crypto/sha256` for hashing. Never MD5 or SHA-1.
- Use ECDSA P-256 for signing (the only supported curve).
- Do not configure TLS cipher suites -- Go's defaults are correct.
- Do not set `InsecureSkipVerify: true` anywhere.

## Code style

### General

- **ASCII only.** All generated code, comments, error messages, documentation,
  and commit messages must contain only printable ASCII characters (U+0000 to
  U+007F). No em dashes, en dashes, curly quotes, Unicode arrows, box-drawing
  characters, or other non-ASCII codepoints. Use `--` instead of em dash,
  `-` instead of en dash, `->` instead of arrows, `"` instead of curly quotes.
- **English (US) only.** All code, comments, error messages, log output, and
  documentation must be written in US English. Use US spellings (e.g.,
  "initialize" not "initialise", "color" not "colour").
- No ampersand in generated text -- use "and".
- Run `gofmt` (or `gofumpt`). No deviations.
- Maximum function length: 80 lines, 50 statements. If a function is longer,
  split it into focused helpers.
- Maximum cyclomatic complexity: 15. Reduce with early returns and guard
  clauses.

### Naming

- Package names: short, lowercase, singular. No `util`, `common`, `helper`.
- Avoid stutter: `registry.Client` not `registry.RegistryClient`.
- Receiver names: one or two letters, consistent within a type (`c` for
  `Client`, `d` for `Deployer`, `s` for `State`).
- Acronyms are all-caps: `URL`, `HTTP`, `ID`, `SBOM`, `OCI`, `TLS`, `DAG`.
- Sentinel errors: `var ErrNotFound = errors.New("not found")`.
- Custom error types: suffix with `Error` (`BuildError`, `ValidationError`).

### Error handling

- Always check errors. No blank identifier for error returns (`_ = f()`).
- Wrap with context using `%w`: `fmt.Errorf("step %q: %w", name, err)`.
- Handle errors once -- either log or return, never both.
- Use `errors.Is` and `errors.As` for error checking, not string matching.

### Interfaces

- Define interfaces at the consumer side, not the producer side.
- Keep interfaces small (1-2 methods).
- Do not create interfaces preemptively -- start with concrete types and
  extract when testing or multiple implementations require it.
- "Accept interfaces, return structs."

### Documentation

- Every exported name must have a doc comment starting with the name.
- Package-level documentation goes in `doc.go` or the primary file's header.
- Comments are complete sentences with a period at the end.

### Context

- `context.Context` is always the first parameter, named `ctx`.
- Never store context in a struct field.
- Use `context.WithTimeout` for operations that may hang (registry pulls,
  container execution).

## Testing rules

### All tests must

- Use table-driven subtests with `t.Run`.
- Pass with `-race` enabled.
- Not require external dependencies (no podman, no network, no registry).
- Test both success and error paths.
- Use `t.TempDir()` for file system tests (auto-cleaned).
- Use `t.Helper()` in test helper functions.

### Testing container operations

Container operations are tested against `httptest.TLS` mock servers that
simulate the podman libpod REST API over TLS. TCP connections always
require server-TLS (unencrypted TCP is rejected), so all test engines
must use ephemeral PKI certificates.

The PKI helpers live in `internal/container/testpki_test.go` and provide:
- `newTLSTestEngine(t, handler)` -- server-only TLS (server cert verified).
- `newMTLSTestEngine(t, handler)` -- mutual TLS (both sides present certs).

For packages outside `internal/container/` (e.g., `deploy_test`), copy
the PKI generation inline or factor a shared test helper.

```go
// Server-only TLS (most tests)
eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}))

// Mutual TLS (identity and attestation tests)
eng := newMTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}))
```

Never use plaintext `httptest.NewServer` with `tcp://` -- `newHTTPClient`
rejects unencrypted TCP connections.

### Testing container connections

All container engine tests use TLS with ephemeral PKI generated via
Go's `crypto/x509`. The test helper `newTLSTestEngine` in
`internal/container/testpki_test.go` generates a CA and server cert per
test. `newMTLSTestEngine` adds a client cert for mutual TLS tests.
There is no plaintext HTTP fallback.

For integration tests against a real podman socket over TCP, use caddy
as a TLS-terminating reverse proxy:

    caddy reverse-proxy \
        --from 127.0.0.1.sslip.io:8443 \
        --to unix//run/user/1000/podman/podman.sock \
        --internal-certs

Set `STRIKE_INTEGRATION=1` to enable integration tests.

### Coverage targets

- Target: 100% statement coverage for all packages except generated code.
- Coverage must not decrease on any merge request.
- Assertion-free tests that execute code without verifying results are not
  acceptable.
- Use `go test -coverprofile=coverage.out -covermode=atomic ./...` to measure.

### Fuzz testing

For input parsers and validators, add fuzz tests:

```go
func FuzzParseRef(f *testing.F) {
    f.Add("step.output")
    f.Add("")
    f.Add("...")
    f.Fuzz(func(t *testing.T, input string) {
        _, _, _ = ParseRef(input) // must not panic
    })
}
```

## Makefile targets

```sh
make build      # CGO_ENABLED=0 go build ./cmd/strike (runs generate first)
make specs      # CUE -> JSON Schema (specs/lane.schema.json, specs/attestation.schema.json)
make generate   # specs + gengotypes -> internal/lane/cue_types_lane_gen.go
make golden     # update golden test fixtures
make check      # lint + test + vuln + build (CI entry point)
```

### Environment variables

- `CONTAINER_HOST` -- container engine address (`unix://` or `tcp://`)
- `CONTAINER_TLS_CERT` -- client certificate PEM path (enables mTLS for TCP)
- `CONTAINER_TLS_KEY` -- client key PEM path (enables mTLS for TCP)
- `CONTAINER_TLS_CA` -- CA certificate PEM path (pins CA for TCP; system store if unset)
- `SOURCE_DATE_EPOCH` -- Unix timestamp for reproducible builds
- `STRIKE_AUDIT` -- enable request audit logging to stderr
- `STRIKE_INTEGRATION` -- enable integration tests

## What not to do

- Do not add a `go:generate` directive for anything other than CUE codegen.
- Do not introduce build tags. Tests must work with plain `go test ./...`.
- Do not add `//nolint` without a written justification in a code comment.
- Do not embed configuration files other than the CUE schemas in `specs/`.
- Do not use `init()` functions.
- Do not use global mutable state (package-level `var` with mutation).
- Do not add logging frameworks. Use `fmt.Printf` for user output, `log.Fatal`
  for fatal errors, `fmt.Fprintf(os.Stderr, ...)` for warnings.
- Do not refactor main.go into a "framework" or "engine" -- the procedural
  orchestration is intentional and auditable.
- Do not create wrapper types around standard library types without clear need.

## Commit messages

- First line: imperative mood, max 72 characters, no period.
- Reference issue numbers where applicable.
- Examples: `fix path traversal in tar extraction`, `add fuzz test for ParseRef`,
  `remove unused hashDir size buffer allocation`.

## After each implementation step

Run `make lint` (or `golangci-lint run ./...`) after every code change and
fix all findings before moving on. Do not batch lint fixes at the end --
catching issues immediately prevents them from compounding. The linter
enforces `errcheck`, `goconst`, `staticcheck`, and other rules that are
easy to miss during development.

## Before submitting

Run the full quality gate:

```sh
golangci-lint run ./...
go test -race -coverprofile=coverage.out -covermode=atomic ./...
deadcode ./...
govulncheck ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike
```

All five commands must succeed with zero warnings and zero findings.
`deadcode` reports functions unreachable from `main()`. All exported
functions must be reachable from `main` or wired through interface
dispatch. Do not add dead code -- wire it in or do not write it.
