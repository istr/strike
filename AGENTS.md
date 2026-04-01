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

1. **No shell execution.** Never use `exec.Command("sh", "-c", ...)`,
   `exec.Command("bash", ...)`, or any shell interpreter anywhere. All
   external commands use `exec.Command("binary", "arg1", "arg2")` with
   separate arguments. This is a security invariant, not a style preference.

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

## Package structure

```
cmd/strike/main.go   CLI entry, dependency wiring, lane execution orchestration
internal/
  lane/              Pipeline definitions, CUE schema, DAG, state, digests
  executor/          Container execution, OCI pack, signing, SBOM, security profile
  registry/          OCI registry operations, caching, spec hashing
  deploy/            Deployment with mandatory state attestation
```

Do not create new packages under internal/ without discussion. Do not create
`pkg/`, `util/`, `common/`, `helper/`, `models/`, `types/`, or `interfaces/`
packages.

### Key files

- `internal/lane/schema.cue` -- The CUE schema is the source of truth for lane
  definitions. After editing, run `cue exp gengotypes ./internal/lane/` to
  regenerate `internal/lane/cue_types_lane_gen.go`. Never edit the generated
  file by hand.
- `internal/executor/step_security_profile.go` -- Hardened podman flags. These
  are constants, not configurable by lane definitions. Treat changes here as
  security-critical.
- `internal/executor/sign.go` -- ECDSA P-256 signing. Uses `crypto/rand`, never
  `math/rand`.
- `cmd/strike/main.go` -- Orchestrates lane execution. Long but intentionally
  procedural. Do not abstract it into a framework.

## Security rules

### Command execution

All external binary calls must:
- Use `exec.Command` or `exec.CommandContext` with separate arguments.
- Reference binaries by known name (podman, kubectl, curl, cosign).
- Never interpolate untrusted input into command strings.
- Propagate `context.Context` for cancellation and timeout.

```go
// CORRECT
cmd := exec.CommandContext(ctx, "podman", "inspect", "--format", "{{.Digest}}", imageRef)

// WRONG -- shell injection risk
cmd := exec.Command("sh", "-c", "podman inspect " + imageRef)

// WRONG -- no context propagation
cmd := exec.Command("podman", "inspect", imageRef)
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

### Cryptography

- Use `crypto/rand` for all random number generation. Never `math/rand`.
- Use `crypto/sha256` for hashing. Never MD5 or SHA-1.
- Use ECDSA P-256 for signing (the only supported curve).
- Do not configure TLS cipher suites -- Go's defaults are correct.
- Do not set `InsecureSkipVerify: true` anywhere.

## Code style

### General

- Language: English for all code, comments, error messages, documentation.
- No ampersand in generated text -- use "and" (English) or "und" (German).
- ASCII only in source files.
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

### Testing external commands

Do not invoke real external binaries in unit tests. Use one of:
1. **Interface mocks** (preferred) -- define a `CommandRunner` interface,
   production code uses the real implementation, tests use a mock.
2. **TestHelperProcess pattern** -- only at the thinnest boundary layer where
   the interface is implemented.

```go
// Interface for testing
type CommandRunner interface {
    Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Mock for tests
type mockRunner struct {
    output []byte
    err    error
}

func (m *mockRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
    return m.output, m.err
}
```

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
make build      # CGO_ENABLED=0 go build ./cmd/strike
make generate   # cue exp gengotypes ./internal/lane/
make schema     # cue export to OpenAPI JSON
```

## What not to do

- Do not add a `go:generate` directive for anything other than CUE codegen.
- Do not introduce build tags. Tests must work with plain `go test ./...`.
- Do not add `//nolint` without a written justification in a code comment.
- Do not embed configuration files other than `schema.cue`.
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

## Before submitting

Run the full quality gate:

```sh
golangci-lint run ./...
go test -race -coverprofile=coverage.out -covermode=atomic ./...
govulncheck ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike
```

All four commands must succeed with zero warnings and zero findings.
