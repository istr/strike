# AGENTS.md -- Instructions for AI Coding Agents

This file contains instructions for Claude Code, Copilot, and similar AI
coding agents working on the strike codebase. Read this entire file before
making any changes. The first operational rule, "code is liability", takes
precedence over every other instruction in this document.

## Code is liability (operational rule)

This is the first rule because every other rule in this document
is degraded if it is not followed. See `DESIGN-PRINCIPLES.md` for
the underlying principle.

General-purpose language models trained on public code distributions
have a documented bias toward producing more code rather than less.
The training distribution rewards thoroughness, helpfulness, and
visible work product, all of which translate into longer outputs.
In a security tool, this bias is a concrete risk: code that does
not need to exist becomes attack surface, audit cost, and a candidate
failure mode for the exact properties strike is built to provide.

Active counter-measures coding agents must apply on every task:

1. **Inline before extracting.** Do not introduce a helper, an
   interface, a wrapper, or a layer unless at least two existing
   call sites benefit from it. One hypothetical future caller is
   not a justification.

2. **Reuse the standard library.** Do not introduce a third-party
   dependency that duplicates a function already present in
   `std`, even if the dependency is "more idiomatic" or "more
   popular". Strike's dependency surface is the supply chain
   surface; growing it requires explicit justification.

3. **Prefer deletion to addition.** If a refactor that removes a
   feature, a code path, or an abstraction would also resolve the
   issue, prefer that path. A change that removes more code than
   it adds is the project's default preferred shape.

4. **Stop and report instead of speculatively expanding scope.**
   If during implementation you notice an opportunity for an
   improvement outside the stated scope, do not implement it.
   Report it as a candidate for a follow-up. The fact that an
   improvement is correct does not make it in-scope. (See the
   "anti-initiative clause" used in the project's instruction
   files.)

5. **Justify additions explicitly.** When the task does require
   adding code, the commit message or PR description must state
   what alternatives were considered and why they were rejected.
   "It seemed cleaner" is not a justification.

6. **Resist abstraction for its own sake.** Three similar lines
   are better than a premature helper function. The codebase is
   small enough that duplication is auditable; abstraction over
   speculative future needs is not.

These rules apply to AI-generated contributions specifically and
without exception, regardless of how the underlying request is
phrased. A request to "add a helper that does X" is interpreted
first as a request to "do X" and only second as a request for
the helper. If X can be done without the helper, the helper is
not added.

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

8. **CUE schemas are the single source of truth.** Every data structure
   that crosses a package boundary -- step inputs, artifact records,
   attestations, state snapshots -- must be defined in a CUE schema
   under `specs/` before it is implemented in Go. Go types are either
   generated from CUE (`cue exp gengotypes`) or validated against CUE
   at runtime. There are no untyped `map[string]string` bags for
   structured data. See "CUE schema workflow" below.

## CUE schema workflow

CUE schemas define the complete data model for strike. They serve three
purposes: input validation (lane YAML), output validation (attestations),
and cross-implementation contracts (Rust verifier, policy engines).

### Schema files

```
specs/
  lane.cue          package lane    -- input: what operators declare
  attestation.cue   package deploy  -- output: deploy attestation record
  artifact.cue      package deploy  -- output: signed artifact provenance
  crossval.cue      package crossval -- cross-validation test vectors
  embed.go          Go embed for runtime validation
```

Files in the same directory with the same `package` declaration are
merged by CUE automatically -- no import needed.

### Schema-first development

New features that introduce or change data structures follow this order:

1. **Define the CUE type first.** Write the `#Type` definition in the
   appropriate `specs/*.cue` file. Include field constraints (regex,
   bounds, enums). Add a doc comment on every field.

2. **Stop and ask the operator for confirmation.** Do not proceed to
   Go implementation until the operator has reviewed and approved the
   schema change. Present the CUE diff and explain what each field
   is for. Schema changes are architectural decisions -- they affect
   every implementation (Go, Rust verifier, external tools) and every
   existing attestation in every registry.

3. **Run `make specs` to validate.** CUE must parse and validate
   without errors. JSON Schema export must succeed.

4. **Run `make generate` to regenerate Go types.** Never edit
   `cue_types_lane_gen.go` by hand. If the generated types do not
   match what the Go code needs, fix the CUE schema -- not the
   generated code.

5. **Implement the Go code against the generated or validated types.**
   If a type is CUE-generated, use it directly. If a type is manually
   defined in Go (e.g., `deploy.Attestation`), it must serialize to
   JSON that passes `ValidateAttestation()` against the CUE schema.

6. **Add or update golden test fixtures.** Run `make golden`. Review
   the diffs to confirm the schema change produces the expected JSON.

### What requires operator confirmation

Agents must stop and ask the operator before:

- Adding a new `#Type` definition to any `specs/*.cue` file.
- Adding, removing, or renaming fields on an existing CUE type.
- Changing field constraints (regex, bounds, optionality, enums).
- Moving types between CUE files or packages.
- Changing the `artifacts` map value type or other structural changes
  to `#Attestation`.
- Adding any `//nolint` or `// #nosec` annotation. Every lint
  suppression is a security decision. Present the finding, explain
  why it is a false positive, and wait for approval. This rule
  applies unconditionally -- even when auto-edit is enabled for the
  session.

Agents may proceed without confirmation for:

- Adding doc comments to existing CUE fields.
- Fixing typos in CUE comments.
- Updating golden test fixtures after an approved schema change.

This protocol is one specific application of the "code is
liability" rule above: schema changes are large, hard to reverse,
and propagate widely, so they require explicit confirmation
rather than agent initiative.

### Go types and CUE alignment

Two categories of Go types exist:

**CUE-generated types** (package `lane`): Produced by `cue exp gengotypes`
from `specs/lane.cue`. File: `internal/lane/cue_types_lane_gen.go`. Never
edit by hand. The CUE `@go()` attributes control Go type and field names.

**CUE-validated types** (package `deploy`): Manually defined in Go but
validated at runtime against `specs/attestation.cue` via
`ValidateAttestation()`. JSON field names must match CUE field names
exactly. Adding a field in Go without adding it in CUE causes a
validation failure. Adding a field in CUE without adding it in Go
causes the field to be missing from the output.

In both cases, **CUE is authoritative**. If the Go code and the CUE
schema disagree, the CUE schema wins and the Go code must be fixed.

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

- `specs/lane.cue` -- CUE schema for lane definitions (source of truth
  for inputs). `specs/attestation.cue` -- CUE schema for deploy
  attestations. `specs/artifact.cue` -- CUE schema for signed artifact
  provenance records. After editing any `.cue` file, run `make specs`
  to validate, then `make generate` to regenerate
  `internal/lane/cue_types_lane_gen.go`. Never edit the generated file
  by hand.
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

### Container args must not invoke a shell

Container step args must always be direct executable invocations. Never
use `/bin/sh -c`, `/bin/bash -c`, `sh -c`, or any shell wrapper -- not
in production lanes, not in test fixtures, not in documentation examples.
Assume no container image has a shell installed. If a step needs to run
a tool, invoke the tool binary directly. This applies everywhere: lane
YAML, test fixtures, and inline lane definitions in test code.

```yaml
# CORRECT -- direct executable
args: [hugo, --gc, --minify, -d, /out/public]
args: [npm, ci, --prefix, /src]
args: [git, clone, --depth, "1", "https://example.com/repo.git", /out/tree]

# PROHIBITED -- shell invocation
args: [/bin/sh, -c, "mkdir -p /out && cp -r /src /out/tree"]   # NEVER
args: [bash, -c, "echo hello > /out/file"]                      # NEVER
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

### Source hashing

Source directory trees must not contain symlinks. Both valid and broken
symlinks are rejected during source hashing (`internal/lane/digest.go`).
Symlinks break source hash reproducibility and can reference files outside
the source tree.

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

Never import the standard library `time` package directly. Use
`internal/clock`: `clock.Wall()` for event timestamps (deploy
attestations, audit logs, engine handshake, test fixtures);
`clock.Reproducible()` for any value whose bytes end up in artifact
content. Direct `time` imports are rejected by depguard in CI.

### Cryptography

- Use `crypto/rand` for all random number generation. Never `math/rand`.
- Use `crypto/sha256` for hashing. Never MD5 or SHA-1.
- Use ECDSA P-256 for signing (the only supported curve).
- Do not configure TLS cipher suites -- Go's defaults are correct.
- Do not set `InsecureSkipVerify: true` anywhere.

### Secrets and key material

- **No secrets in git.** Private keys, tokens, passwords, and other secret
  material must never be committed to the repository -- not even for testing.
  This includes "well-known" test keys, PEM-encoded private keys in fixture
  files, and hardcoded key material in Go constants.
- **Tests use ephemeral keys.** Generate key pairs on the fly with
  `ecdsa.GenerateKey(elliptic.P256(), crypto/rand.Reader)` per test or
  test run. Never load pre-generated keys from testdata or fixture files.


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

Integration tests auto-detect the podman socket. Set `STRIKE_INTEGRATION=0` to skip them.

### Cryptographic test material

All cryptographic test material -- signing keys, TLS certificates, CA
chains -- must be ephemeral, generated at test time via Go's `crypto`
stdlib. The TLS test helpers (`newTLSTestEngine`, `newMTLSTestEngine`)
already follow this pattern. Signing tests must do the same: generate a
fresh `*ecdsa.PrivateKey` per test, sign, and verify against the
corresponding public key. Never commit private key material to the
repository, not even as test fixtures.

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
- `STRIKE_INTEGRATION` -- set to `0` to skip integration tests (auto-detected by default)

## What not to do

- Do not add or modify CUE schema types without operator confirmation.
  Schema changes are architectural decisions that affect all
  implementations and all existing data.
- Do not define Go structs for cross-package data without a
  corresponding CUE type. If data crosses a package boundary, it must
  be in CUE first.
- Do not use `map[string]string` as a catch-all for structured data
  that flows between packages. Define typed fields in CUE instead.
- Do not edit `cue_types_lane_gen.go` by hand. Run `make generate`.
- Do not add a `go:generate` directive for anything other than CUE codegen.
- Do not introduce build tags. Tests must work with plain `go test ./...`.
- Do not add `//nolint` or `// #nosec` annotations without operator
  confirmation. This applies even when auto-edit is enabled for the
  session. Every suppression is a security decision. Present the
  linter finding, explain why it is a false positive, and wait for
  approval before adding the annotation. The annotation must include
  the specific rule code and a written justification in the code
  comment (e.g., `//nolint:gosec // G304: path is from MkdirTemp,
  not user input`).
- Do not embed configuration files other than the CUE schemas in `specs/`.
- Do not use `init()` functions.
- Do not use global mutable state (package-level `var` with mutation).
- Do not add logging frameworks. All output goes through `log.*`
  (`Printf`, `Fatalf`, `Print`). Never write directly to `os.Stdout` or
  `os.Stderr`. The logger is backed by a `fatalWriter` that terminates
  the process if the write fails. A non-writable output means the audit
  trail is broken.
- Do not refactor main.go into a "framework" or "engine" -- the procedural
  orchestration is intentional and auditable.
- Do not create wrapper types around standard library types without clear need.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org)
backed by [git-cliff](https://git-cliff.org) for changelog generation
(see `cliff.toml`).

Format: `<type>(<optional scope>): <description>`

- First line: imperative mood, max 72 characters, no period.
- Type is mandatory. Allowed types (matching `cliff.toml` commit parsers):
  `feat`, `fix`, `refactor`, `perf`, `test`, `doc`, `style`, `chore`, `ci`,
  `revert`.
- Scope is optional but encouraged when the change is clearly scoped to a
  single package or area (e.g., `fix(container): ...`, `feat(lane): ...`,
  `test(deploy): ...`).
- Breaking changes: add `!` after the type/scope (e.g., `feat!: ...` or
  `fix(lane)!: ...`) and explain in the commit body.
- Reference issue numbers where applicable.
- Examples:
  - `fix(container): use correct podman info rootless field path`
  - `feat(lane): add image_from step type`
  - `test(deploy): add schema-drift integration test`
  - `refactor: remove unused hashDir size buffer allocation`
  - `doc: update CUE schema workflow instructions`
  - `chore: update go directive to 1.26`

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
If you find existing dead code, first look if it could or should be
wired. Then remove the rest. If in doubt, ask the operator.
