# Development Guidelines

This document defines the code security, quality, and style standards for
strike. It serves as the authoritative reference for code reviews, CI
enforcement, and contributor onboarding.

## 1. Security

strike is a CI/CD executor that handles signing keys, secrets, and arbitrary
container images. Security is not a feature -- it is a constraint that shapes
every design decision.

### 1.1 Command injection prevention

strike communicates with the container engine via REST API over a Unix
socket (`internal/container/`). There are no `exec.Command` calls for
container operations. This eliminates command injection as an attack
vector for container operations entirely.

The only remaining `exec.Command` is in `internal/deploy/deploy.go` for
user-defined state capture commands (the "command" capture type). This is
intentional and annotated with `//nolint:gosec`.

**Rule: never invoke a shell.** No `exec.Command("sh", "-c", ...)` anywhere.

```go
// Correct: use the container.Engine interface
exitCode, err := engine.ContainerRun(ctx, container.RunOpts{
    Image: imageRef,
    Cmd:   []string{"build", "-o", "/out/bin"},
})

// Prohibited: exec.Command for container operations
exec.Command("podman", "run", imageRef)

// Prohibited: shell interpretation
exec.Command("sh", "-c", "podman push "+imageRef)
```

gosec rule G204 and golangci-lint enforce this. The architecture eliminates
G204 findings by design rather than by `//nolint` directives.

### 1.2 Path traversal prevention

strike processes tar archives (OCI image layers, cache artifacts) and mounts
host paths into containers. Path traversal is the second-highest risk.

**Rule: `filepath.Clean` is not a security control.** It computes the shortest
equivalent path but does not prevent escaping a directory boundary.
`filepath.Join("/safe/", filepath.Clean("../../etc/passwd"))` yields
`/etc/passwd`.

**Use `filepath.IsLocal` (Go 1.20+) for untrusted paths:**

```go
func safePath(base, untrusted string) (string, error) {
    if !filepath.IsLocal(untrusted) {
        return "", fmt.Errorf("path traversal: %q", untrusted)
    }
    full := filepath.Join(base, untrusted)
    // Double-check: resolved path must be under base
    if !strings.HasPrefix(full, filepath.Clean(base)+string(os.PathSeparator)) {
        return "", fmt.Errorf("path escape: %q resolves outside %q", untrusted, base)
    }
    return full, nil
}
```

**Tar extraction must validate every entry:**

```go
for {
    header, err := tr.Next()
    if err == io.EOF { break }
    if err != nil { return err }

    // Reject path traversal
    if !filepath.IsLocal(header.Name) {
        return fmt.Errorf("path traversal in tar: %q", header.Name)
    }

    // Reject symlinks pointing outside
    if header.Typeflag == tar.TypeSymlink {
        if !filepath.IsLocal(header.Linkname) {
            return fmt.Errorf("symlink traversal in tar: %q -> %q", header.Name, header.Linkname)
        }
    }

    // Reject device nodes, FIFOs, etc.
    switch header.Typeflag {
    case tar.TypeReg, tar.TypeDir, tar.TypeSymlink:
        // allowed
    default:
        return fmt.Errorf("disallowed tar entry type %d: %q", header.Typeflag, header.Name)
    }

    // Enforce size limit (prevent decompression bombs)
    if header.Size > maxFileSize {
        return fmt.Errorf("tar entry %q exceeds size limit: %d > %d", header.Name, header.Size, maxFileSize)
    }
}
```

### 1.3 Secret handling

Secrets flow: lane definition (source URI) -> strike process memory ->
container environment variable. At no point may a secret value:

- Appear in process arguments (visible in `ps aux`).
- Be included in log output or error messages.
- Be written to disk (cache artifacts, temporary files).
- Be included in OCI image layers or annotations.

The current implementation passes secrets via `os.Setenv` combined with
`--env NAME` (name only, no value in args). Future work: wrap secret values
in a `SecretString` type with `String() string` returning `[REDACTED]`.

### 1.4 Cryptography

- Random numbers: `crypto/rand` only. `math/rand` is prohibited for any
  purpose (gosec G404).
- Hashing: SHA-256 (`crypto/sha256`). MD5 and SHA-1 are prohibited (gosec
  G401).
- Signing: ECDSA P-256 via `crypto/ecdsa`. The signature format is raw
  `r||s` (32 bytes each, zero-padded), base64-encoded.
- Key encryption: scrypt KDF with NaCl secretbox (cosign-compatible format).
- TLS: Go stdlib defaults. Do not configure cipher suites. Do not set
  `InsecureSkipVerify: true` (gosec G402).
- Constant-time comparison: use `crypto/subtle.ConstantTimeCompare` for
  comparing MACs, signatures, or other security-critical byte slices.

### 1.5 Error message security

Error messages at package boundaries (where they may reach the user) must not
contain host paths, secret values, internal hostnames, or stack traces:

```go
// Internal error (for logging, debugging)
fmt.Errorf("registry auth to %s with token %s: %w", registryURL, token, err) // WRONG

// Safe error (crosses package boundary)
fmt.Errorf("registry authentication failed: %w", err) // CORRECT
```

### 1.6 Security toolchain

Run in CI on every change:

| Tool | Purpose | Config |
|------|---------|--------|
| golangci-lint (gosec) | Pattern-based security scanning | `.golangci.yml` |
| govulncheck | Reachable vulnerability detection | `govulncheck ./...` |
| go test -race | Data race detection | Always enabled in CI |

gosec rules to watch for:
- G101: Hardcoded credentials
- G107: SSRF via variable URL
- G110: Decompression bomb (`io.Copy` without limit)
- G204: Subprocess with variable command
- G304: File path from variable (path traversal)
- G401: Weak hash (MD5, SHA-1)
- G402: TLS InsecureSkipVerify
- G404: `math/rand` for security

## 2. Testing

### 2.1 Test structure

All tests use the table-driven pattern with named subtests:

```go
func TestParseRef(t *testing.T) {
    tests := []struct {
        name       string
        input      string
        wantStep   string
        wantOutput string
        wantErr    bool
    }{
        {"valid ref", "build.binary", "build", "binary", false},
        {"empty string", "", "", "", true},
        {"no dot", "build", "", "", true},
        {"empty step", ".binary", "", "", true},
        {"empty output", "build.", "", "", true},
        {"multiple dots", "a.b.c", "a", "b.c", false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            step, output, err := ParseRef(tt.input)
            if (err != nil) != tt.wantErr {
                t.Fatalf("ParseRef(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
            }
            if step != tt.wantStep {
                t.Errorf("step = %q, want %q", step, tt.wantStep)
            }
            if output != tt.wantOutput {
                t.Errorf("output = %q, want %q", output, tt.wantOutput)
            }
        })
    }
}
```

Rules:
- Every `t.Run` subtest must contain at least one assertion.
- Test both success and error paths.
- Test edge cases: empty input, nil pointers, zero values, maximum values.
- Use `t.Fatalf` for precondition failures, `t.Errorf` for assertion failures
  (allows remaining assertions to run).

### 2.2 Testing external commands

Unit tests must not require podman, kubectl, or any external binary. Two
approaches, in order of preference:

**Approach 1: Interface-based mocking (preferred)**

Define a small interface at the consumer side. Production code uses the real
implementation. Tests use a hand-written mock.

```go
// Consumer defines what it needs
type ContainerRunner interface {
    Run(ctx context.Context, image string, args []string, mounts []Mount) error
    Inspect(ctx context.Context, ref string) (string, error)
}

// Production implementation
type PodmanRunner struct{}

func (p *PodmanRunner) Run(ctx context.Context, image string, args []string, mounts []Mount) error {
    cmdArgs := buildPodmanArgs(image, args, mounts)
    return exec.CommandContext(ctx, "podman", cmdArgs...).Run()
}

// Test mock
type fakeRunner struct {
    runErr     error
    inspectOut string
    inspectErr error
}

func (f *fakeRunner) Run(_ context.Context, _ string, _ []string, _ []Mount) error {
    return f.runErr
}

func (f *fakeRunner) Inspect(_ context.Context, _ string) (string, error) {
    return f.inspectOut, f.inspectErr
}
```

**Approach 2: TestHelperProcess pattern (boundary layer only)**

For the thinnest layer where `exec.Command` is actually called, use the Go
standard library's own pattern:

```go
func TestHelperProcess(t *testing.T) {
    if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
        return
    }
    defer os.Exit(0)
    // Parse args after "--" and produce expected output
}
```

Use this only where interface mocking is not feasible (e.g. testing the
`PodmanRunner` implementation itself).

### 2.3 File system testing

- Use `t.TempDir()` for tests that write files. It is automatically cleaned
  up after the test.
- Use `testing/fstest.MapFS` for tests that only read files (in-memory, no
  disk I/O).
- For crypto tests, generate deterministic test keys in `TestMain` or test
  setup, not at package init time.

### 2.4 Coverage

Target: 100% statement coverage for all non-generated code. Measure with:

```sh
go test -coverprofile=coverage.out -covermode=atomic ./...
go tool cover -func=coverage.out
```

Exclude from coverage measurement:
- `lane/cue_types_lane_gen.go` (generated code)

Focus coverage investment on:
- All error return paths (what happens when podman fails, when the registry is
  unreachable, when a secret is missing)
- Security-sensitive code (path validation, digest verification, signing)
- Edge cases (empty inputs, malformed image refs, concurrent access to State)

### 2.5 Integration tests

Integration tests that require external dependencies (podman, a registry) are
guarded by an environment variable:

```go
func requireIntegration(t *testing.T) {
    t.Helper()
    if os.Getenv("STRIKE_INTEGRATION") == "" {
        t.Skip("set STRIKE_INTEGRATION=1 to run integration tests")
    }
}
```

This ensures `go test ./...` always succeeds without external dependencies.

### 2.6 Fuzz testing

Add fuzz tests for all input parsers and validators:
- `lane.Parse` (YAML/CUE validation)
- `lane.ParseRef` (step.output reference parsing)
- `registry.SpecHash` (cache key computation)
- `executor.validateContentType` (magic byte validation)

Fuzz tests must not panic on any input. Failing inputs are saved to
`testdata/fuzz/` and run as regression tests automatically.

## 3. Code style

### 3.1 Formatting

- `gofmt` is the baseline. Prefer `gofumpt` for stricter formatting.
- `goimports` for import organization (stdlib, blank line, external).
- No manual import grouping beyond the standard two groups.

### 3.2 Naming conventions

**Packages:** Short, lowercase, singular nouns. The package name is the import
context for all its identifiers. Avoid stutter: `registry.Client` not
`registry.RegistryClient`.

Never create packages named `util`, `common`, `helper`, `models`, `types`, or
`interfaces`. These group by kind rather than responsibility.

**Variables and parameters:**
- Short names for short scopes: `i`, `err`, `ctx`, `buf`, `f`, `h`.
- Longer names for larger scopes: `imageDigest`, `signatureVerifier`.
- Loop variables: `i` for index, `name` or descriptive noun for range value.

**Receivers:** One or two letters, consistent within a type. `s` for `State`,
`c` for `Client`, `d` for `Deployer`, `r` for `Run`.

**Acronyms:** All-caps regardless of position: `URL`, `HTTP`, `ID`, `SBOM`,
`OCI`, `TLS`, `DAG`, `ECDSA`, `YAML`, `JSON`, `CUE`.

**Errors:**
- Sentinel: `var ErrNotFound = errors.New("not found")` -- prefix with `Err`.
- Types: `type BuildError struct { ... }` -- suffix with `Error`.

**Constructors:** `New()` when a package exports a single main type.
`NewClient()`, `NewState()` when multiple constructors exist.

### 3.3 Error handling

```go
// Wrap with context at each call site
if err := registry.Pull(tag); err != nil {
    return fmt.Errorf("step %q: pull cache artifact: %w", stepName, err)
}

// Check error identity
if errors.Is(err, ErrNotFound) {
    // handle not-found case
}

// Check error type
var buildErr *BuildError
if errors.As(err, &buildErr) {
    // access buildErr.Step, buildErr.ExitCode, etc.
}

// Handle errors once: return OR log, never both
```

Error strings: lowercase, no trailing punctuation, no "failed to" prefix.
The caller adds context. Chain reads naturally: `step "build": pull cache
artifact: connection refused`.

### 3.4 Interface design

Define interfaces at the consumer side, not the producer side. Keep them
small -- one or two methods. Extract interfaces only when you have a material
need (testing, multiple implementations, decoupling packages):

```go
// In deploy/ -- defines only what deploy needs from the signer
type ImageSigner interface {
    Sign(ctx context.Context, digest string) error
}

// In deploy/ -- constructor accepts the interface
func NewDeployer(signer ImageSigner) *Deployer { ... }
```

Do not export interfaces before the need is proven. Do not create interfaces
that mirror a single concrete type's full method set.

### 3.5 Function design

- Single responsibility. If a function does two things, split it.
- Maximum 80 lines, 50 statements (enforced by golangci-lint `funlen`).
- Use guard clauses and early returns to reduce nesting.
- Maximum nesting depth: 4 levels (enforced by `nestif`).

```go
// Prefer early return (guard clause)
func process(input string) error {
    if input == "" {
        return fmt.Errorf("empty input")
    }
    if !isValid(input) {
        return fmt.Errorf("invalid input: %q", input)
    }
    // main logic at minimal indentation
    return doWork(input)
}
```

### 3.6 Documentation

Every exported name has a doc comment. The first sentence is a complete
sentence starting with the element name:

```go
// State tracks artifacts and step results across lane execution.
// All artifact references use "step_name.output_name" keys.
type State struct { ... }

// Register adds an artifact to the state under "step_name.output_name".
func (s *State) Register(stepName, outputName string, a Artifact) error { ... }

// ErrNotFound is returned when an artifact reference cannot be resolved.
var ErrNotFound = errors.New("not found")
```

Package-level doc goes in the package clause comment or a `doc.go` file.

### 3.7 Context propagation

- `context.Context` is always the first parameter, named `ctx`.
- Never store context in a struct.
- Use `context.WithTimeout` for operations that may hang.
- Use `signal.NotifyContext` at the CLI entry point for graceful shutdown.

### 3.8 Concurrency

- The `lane.State` type uses `sync.RWMutex` -- always `defer mu.Unlock()`
  immediately after `Lock()`.
- Use `errgroup.WithContext` for bounded parallel operations.
- Run `go test -race ./...` in CI -- always, no exceptions.
- Do not use `sync.Map` unless profiling shows contention on `sync.RWMutex`.
- Do not use `init()` functions.

## 4. golangci-lint configuration

The project uses a strict `.golangci.yml`. Key settings:

- `errcheck`: check type assertions and blank identifiers.
- `govet`: all analyzers enabled.
- `gosec`: no excluded rules -- all security checks active.
- `gocyclo`: max complexity 15.
- `funlen`: max 80 lines, 50 statements.
- `nestif`: max complexity 5.
- `testpackage`: enforces `_test` package suffix for black-box testing.
- `errorlint`: enforces `%w` wrapping and `errors.Is`/`errors.As`.
- `nolintlint`: requires justification for every `//nolint` directive.

Test files are exempted from `funlen`, `gocyclo`, and `gocognit` because
table-driven tests are naturally longer.

## 5. Dependency policy

The project has five direct dependencies:

| Module | Purpose |
|--------|---------|
| `cuelang.org/go` | CUE schema validation |
| `github.com/CycloneDX/cyclonedx-go` | SBOM generation and parsing |
| `github.com/google/go-containerregistry` | OCI image manipulation |
| `golang.org/x/crypto` | scrypt KDF, NaCl secretbox |
| `gopkg.in/yaml.v3` | YAML parsing |

Adding a dependency requires:
1. Justification that copying is not feasible.
2. `govulncheck` clean report for the new dependency.
3. License compatibility check (MIT, BSD, Apache 2.0 only).
4. Transitive dependency count impact assessment.

Run `go mod verify` in CI to ensure dependency integrity. Commit `go.sum`.
