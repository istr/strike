# Code Style -- Patterns and Anti-Patterns

This document is the authoritative reference for *how strike code is shaped*.
It does not define linter rules (those live in `.golangci.yml`) and it does
not define principles (those live in `DESIGN-PRINCIPLES.md`). It defines the
concrete forms -- the named patterns -- that the project has settled on, so
that the same questions are not relitigated in every PR.

Each pattern below has an anchor name (e.g. `path-confined-io`). PR comments,
ADRs, and CI messages may cite a pattern by anchor:
"violates `CODE-STYLE.md#path-confined-io`".

## How to use this document

- **Authors and AI agents** read this *before* writing code in any
  area covered by a pattern. If a pattern applies, the pattern is used;
  there is no per-call-site judgement.
- **Reviewers** check changes against the discovery rule of each pattern
  that touches the diff. A grep that returns the bad shape is grounds to
  request changes.
- **CI** runs `golangci-lint` with `nolintlint` active. A new `//nolint`
  in a PR is, by policy, a defect: it means either the code violates a
  pattern (fix the code) or a new pattern is required (open an ADR).

## The meta-pattern: the annotation chokepoint

**Rule.** A `//nolint` annotation, when it is genuinely unavoidable, lives
in exactly one small named helper function whose name describes the
operation, and whose package contract justifies the suppression. The
annotation lives once, the callers are annotation-free.

**Bad.** A `//nolint:gosec // G304: path is from t.TempDir()` repeated at
14 call sites. Every reviewer must re-derive the safety argument; one
mistake produces a real bug that the suppression hides.

**Good.** A single `testutil.ReadTemp(t, dir, name)` helper. The
annotation lives inside the helper, with a comment that ties to the
package-level contract ("only called with `t.TempDir()` roots"). The 14
call sites read `data := testutil.ReadTemp(t, dir, "out.json")` and
contain no annotation.

**Rationale.** Annotations are security decisions. A security decision
that is repeated 14 times is 14 places that can drift independently. A
security decision that is hoisted into one helper is one place to audit.
The annotation count is a proxy metric for how localized the project's
exceptions are.

**Discovery.** `grep -rnc '//nolint' --include='*.go' | sort -t: -k2 -rn`.
Any file with more than one annotation is a candidate for hoisting into
a helper.

**Allowed permanent annotations.** As of this writing, the project
sanctions only the following long-lived annotation sites:

| Helper                                            | Linter / code                | Reason                                      |
|---------------------------------------------------|------------------------------|---------------------------------------------|
| `internal/executor.SETPayload` declaration        | `govet` fieldalignment       | Field order is part of the signed payload   |
| `internal/lane.FilePath.Read`                     | `gosec` G304 (optional)      | Validated CLI path chokepoint               |
| `internal/testutil.ReadTemp`                      | `gosec` G304 (optional)      | `t.TempDir()` root contract                 |
| `internal/testutil.WriteTestBinary`               | `gosec` G302                 | Test binary needs owner-exec; 0o700 is minimum viable mode |

Adding any other long-lived annotation requires an ADR.

---

## CUE scalar types and the `@go` annotation `cue-scalar-types`

**Rule.** A scalar value constraint in `contract/primitive/` is a CUE-driven named Go
type. A regex or enum constraint definition (`#Sha256`, `#Identifier`,
`#GitCommit`, `#Base64`, `#Digest`, and so on) carries no `@go` annotation
and surfaces as a named Go type (`type Sha256 string`, ...). A struct field
that references such a definition carries `@go(FieldName)` with no `type=`
override and surfaces with the referenced named type (`Commit GitCommit`,
`Hex Sha256`).

**`@go(-)` is reserved for two structural cases only:**

1. A disjunction (sum type) that is hand-modelled as a Go interface:
   `#ProvenanceRecord`, `#OutputHandle`, `#TLSTrust`, `#EngineConnection`.
   The generator cannot emit a Go sum type, so the union is suppressed and
   the interface is hand-written. CUE needs a discriminator field for
   disjunctions on structs. The name of this field is `type` and MAY also
   be suppressed using the annotation if it is not needed in the implementation.
2. An abstract base constraint whose named Go type is unwanted, for example
   `#Path` (the abstract base for `#AbsPath`/`#RelPath`).

A field-level `type=string` override on a regex scalar is none of these: it
suppresses the named type the constraint exists to provide, and is not used.

**Wire and internal contracts are separate types in separate layers.** A
value that has both a serialized wire form and a computed internal form is
two CUE definitions, not one type behind suppressed codegen. The digest
concern is the worked example: `#Digest` (base-scalars) is the wire string
`type Digest string`; `#DigestRef` (api-digest) is the internal
`type DigestRef struct{...}`; `internal/lane/digest_type.go` bridges them with
`ParseDigest` and `(DigestRef).Wire()`. The generated wire type is amended
with methods in a hand-written sibling file -- gengotypes emits only type
declarations and json tags, so the sibling adds behavior with no `@go(-)` --
never hidden behind a suppressed-codegen struct.

**Rationale.** `@go(-)` doing double duty, legitimately suppressing
disjunctions and illegitimately hiding a hand-written struct, is how the wire
and internal digest forms collapsed into one annotation-hidden type. Keeping
the two uses separate keeps the codegen honest: every non-disjunction scalar
is CUE-driven, and a reviewer reads `@go(-)` as "disjunction or cross-package
base" with no exception.

---

## Type conversions are owned in the type's own package `type-conversion-ownership`

**Rule.** A CUE-driven named type carries its structure from CUE; Go adds
behavior, and a type conversion is behavior. A conversion of such a named type
that appears directly as a call argument -- `f(string(id))`,
`g(primitive.Host(raw))` -- is a defect: it scatters the type's boundary across
every caller. Conversions are owned in exactly one place, the type's own defining
package, through its methods (`(AbsPath).Clean`, `(Digest).Hex`). Everywhere
else, a value is typed end to end.

**Permitted forms.** The conversion is not a call argument when it is a named
assignment (`s := string(id); f(s)`), a composite-literal field
(`T{Name: string(id)}`), a method call on the type (`f(id.String())`), or a bare
return (`return string(id)`). These own or defer the boundary explicitly and are
allowed; the call-argument form is not.

**Enforcement.** `tools/linttypeconv` walks the type-checked AST and fails the
build on any conversion of a strike named type sitting in a call argument, except
within that type's own package -- or its external test package, the same
ownership layer for that package's own test code -- or a site named in the
linter's central allowlist. The allowlist is auditable and editable; each entry
carries the reason a conversion is deferred, and an empty allowlist means the
tree is exhaustively type-clean. `make lint-typeconv` runs it; it is part of
`make check`.

---

## File I/O is path-confined `path-confined-io`

**Rule.** File I/O on a composed or external path goes through `*os.Root`.
`os.Open`, `os.ReadFile`, `os.OpenFile`, `os.Create`, and `os.WriteFile`
called with a path that joins any non-constant component are forbidden
outside `*os.Root`-based helpers.

**Bad.**

```go
path := filepath.Join(scratchDir, "outputs", name)
data, err := os.ReadFile(path) //nolint:gosec // G304: path is under our scratch
```

**Good.**

```go
root, err := os.OpenRoot(scratchDir)
if err != nil {
    return nil, err
}
defer closer.Warn(root, "scratch root")
f, err := root.Open(filepath.Join("outputs", name))
if err != nil {
    return nil, err
}
defer closer.Warn(f, "scratch read")
data, err := io.ReadAll(f)
```

**Rationale.** `os.Root` (Go 1.24+) makes path traversal a structural
impossibility: paths that escape the root cannot be opened, period. This
turns a documented-and-audited security argument into a type-system
guarantee. Existing project example: `cmd/strike/helpers.go::writeToOutputDir`.

**Function signatures.** Functions that read or write files take `*os.Root`
plus a `relative string`, not a host path. Callers open the root once.
`fs.WalkDir(root.FS(), ".", fn)` walks the root tree without ever leaving it.

**Discovery.** Grep for raw I/O on non-constant paths:

```
grep -rn -E 'os\.(Open|ReadFile|WriteFile|OpenFile|Create)\(' --include='*.go' \
  | grep -v '_test.go' \
  | grep -v 'os.Root'
```

Any match outside `internal/lane/path.go` and `cmd/strike/helpers.go` is a
candidate for migration.

**Exception.** Pure constants (`os.ReadFile("contract/lane/lane.cue")`) are fine
when the path is a compile-time string literal; gosec does not flag them.
Use `embed.FS` in preference even there when feasible (see
`embedded-test-fixtures`).

---

## Cleanup errors go through `closer.Warn` / `closer.Remove` `closer-helpers`

**Rule.** `Close` and `RemoveAll` in defer statements use the
`internal/closer` helpers. `defer x.Close() //nolint:errcheck` and
`defer os.RemoveAll(d) //nolint:errcheck` are forbidden.

**Bad.**

```go
defer resp.Body.Close() //nolint:errcheck // best-effort
defer os.RemoveAll(scratchDir) //nolint:errcheck // best-effort
```

**Good.**

```go
defer closer.Warn(resp.Body, "rekor response")
defer closer.Remove(scratchDir, "deploy scratch")
```

**Rationale.** A close failure on a deferred file or socket is a real
environmental signal (filesystem out of space, container engine
disappeared, fd table corrupted) and should appear in audit logs.
`closer.Warn` consumes the error after logging, which is `errcheck`-clean.
`//nolint:errcheck` discards both the error *and* the audit signal.
Close errors that are expected socket/stream shutdowns
(`closer.IsExpectedClose`: EOF, closed conn/file, broken pipe, peer reset)
are silent; real failures warn.

**The helper.**

```go
// internal/closer/closer.go
package closer

func Warn(c io.Closer, context string) {
    if err := c.Close(); err != nil && !IsExpectedClose(err) {
        log.Printf("WARN   %s: close: %v", context, err)
    }
}

func Remove(path, context string) {
    if err := os.RemoveAll(path); err != nil {
        log.Printf("WARN   %s: remove %s: %v", context, path, err)
    }
}
```

**Discovery.**

```
grep -rn -E 'defer .*\.Close\(\) *//nolint' --include='*.go'
grep -rn -E 'defer os\.RemoveAll.*//nolint'  --include='*.go'
```

**Exception.** A `Close` whose return value is part of the function's
normal error path is not deferred -- it is called explicitly and its error
is returned or joined (see `internal/registry/imagewrap.go::extractRegularFile`
for the canonical shape).

---

## Test cleanup uses `testutil.CloseLog` `test-closer-helpers`

**Rule.** Test-side cleanup uses `testutil.CloseLog`. The test's `*testing.T`
is available, so failures route through `t.Logf` (or `t.Errorf` if the
failure should fail the test).

**Bad.**

```go
defer outRoot.Close() //nolint:errcheck // test cleanup
t.Cleanup(func() { ln.Close() }) //nolint:errcheck
```

**Good.**

```go
defer testutil.CloseLog(t, outRoot, "outRoot")
t.Cleanup(func() { testutil.CloseLog(t, ln, "echo listener") })
```

**The helper.**

```go
// internal/testutil/closer.go
package testutil

func CloseLog(t *testing.T, c io.Closer, context string) {
    t.Helper()
    if err := c.Close(); err != nil {
        t.Logf("%s: close: %v", context, err)
    }
}
```

**Discovery.** Same grep as `closer-helpers`, restricted to `*_test.go`.

---

## HTTP test handlers escalate errors `test-http-helpers`

**Rule.** `httptest`-server handlers that call `w.Write`, `w.WriteHeader`
with a body, or `json.NewEncoder(w).Encode` use the `testutil` helpers.
The error is reported to the test via `t.Errorf`, not discarded.

**Bad.**

```go
http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write(fakeResponse(t)) //nolint:errcheck // test helper
})
```

**Good.**

```go
http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    testutil.WriteBody(t, w, fakeResponse(t))
})
```

**The helpers.**

```go
// internal/testutil/http.go
package testutil

func WriteBody(t *testing.T, w http.ResponseWriter, body []byte) {
    t.Helper()
    if _, err := w.Write(body); err != nil {
        t.Errorf("write response body: %v", err)
    }
}

func WriteJSON(t *testing.T, w http.ResponseWriter, v any) {
    t.Helper()
    if err := json.NewEncoder(w).Encode(v); err != nil {
        t.Errorf("encode response: %v", err)
    }
}
```

**Rationale.** A write failure inside a fake Rekor server is exactly the
kind of bug that turns a passing test into a silently-wrong test. The
handler must surface it.

---

## Embedded test fixtures, not runtime `ReadFile` `embedded-test-fixtures`

**Rule.** Test fixtures with a fixed compile-time path are loaded via
`embed.FS`. `os.ReadFile(filepath.Join(testdataDir, name))` is forbidden
in test code where the directory is a package constant.

**Bad.**

```go
const crossvalDir = "../../test/crossval"

data, err := os.ReadFile(filepath.Join(crossvalDir, subdir, name)) //nolint:gosec
```

**Good -- fixtures inside the test package's `testdata/`.**

```go
//go:embed testdata/golden/*.json
var goldenFS embed.FS

data, _ := goldenFS.ReadFile("testdata/golden/" + name)
```

**Good -- fixtures shared across packages (e.g. `test/crossval/`).** Add
a thin package whose only role is to export the embed:

```go
// test/crossval/embed.go
package crossval

import "embed"

//go:embed *
var FS embed.FS
```

Test code:

```go
import "github.com/istr/strike/test/crossval"

data, _ := crossval.FS.ReadFile(subdir + "/" + name)
```

**Rationale.** `embed.FS` is build-time-resolved, so `gosec` G304 does not
fire. Bonus: fixtures travel inside the compiled binary, tests are
hermetic, and the dependency on a relative directory path disappears.
`test/crossval/` is intentionally outside any package's `testdata/`
(see ADR-017): the embed shim preserves that separation while still
giving Go test code a hermetic loader.

**Discovery.**

```
grep -rn 'os.ReadFile' --include='*_test.go' \
  | grep -v 't.TempDir'
```

**Exception.** Fixtures genuinely produced at runtime by the test (e.g.
written to `t.TempDir()` earlier in the test) use `testutil.ReadTemp`.

---

## Fieldalignment is mandatory; JSON tags map fields `fieldalignment-default`

**Rule.** Structs are declared in fieldalignment-clean order: fields grouped
by descending alignment, within each group by descending total size. For JSON
unmarshaling, the JSON tag does the mapping; field order is irrelevant to
behaviour. JSON-field-order mirroring ("matches the API response") is wrong
about `json.Unmarshal` and is not a justification for a `//nolint:govet`.

The full reference -- the amd64/arm64 alignment-group table, the
strike-specific cheat sheet, worked examples, the decision procedure for a new
struct, the CUE-generated-types fix, and the allowed permanent exceptions --
lives in `docs/FIELDALIGNMENT.md`. Consult it before declaring a struct, not
after the linter flags it.

**Discovery.** `golangci-lint run ./...`; the suggested "optimal" struct in a
`fieldalignment:` message is the target.

---
## Marshal-order-sensitive types: one source + reflection contract `marshal-order-contract`

**Rule.** When a struct's field order *does* affect output bytes (e.g. a
struct that is signed and whose canonical JSON serialization must be
byte-stable across implementations), the type lives in exactly one
package and a reflection test pins the field order as a contract. Test
code that needs the same shape imports the production type; it does not
declare a parallel copy.

**Bad.**

```go
// internal/deploy/rekor_test_helper_test.go
type setPayload struct { //nolint:govet // matches Rekor SET layout
    Body           string `json:"body"`
    IntegratedTime int64  `json:"integratedTime"`
    LogID          string `json:"logID"`
    LogIndex       int64  `json:"logIndex"`
}
```

(Plus an identical second copy in another test file.)

**Good.** Export the type once; pin field order with a reflection test:

```go
// internal/executor/rekor.go
type SETPayload struct { //nolint:govet:fieldalignment // field order is signed; pinned by TestSETPayload_FieldOrder
    Body           string `json:"body"`
    IntegratedTime int64  `json:"integratedTime"`
    LogID          string `json:"logID"`
    LogIndex       int64  `json:"logIndex"`
}
```

```go
// internal/executor/rekor_test.go
func TestSETPayload_FieldOrder(t *testing.T) {
    want := []string{"Body", "IntegratedTime", "LogID", "LogIndex"}
    typ := reflect.TypeOf(SETPayload{})
    for i, name := range want {
        if got := typ.Field(i).Name; got != name {
            t.Errorf("Field %d = %q, want %q", i, got, name)
        }
    }
}
```

Test files use `executor.SETPayload` directly; no duplicate type.

**Rationale.** A field-order suppression that is not test-backed is a
silent invariant -- easy to break, no signal when broken. Reflection turns
the suppression's text rationale into an executable contract.

---

## `io.Copy` goroutines use `copier.Forward` `copier-helpers`

**Rule.** Half-duplex forwarding (typical SSH-agent shape) goes through
`internal/copier.Forward`. The helper handles `io.Copy`, half-close, and
expected-close error filtering in one place.

**Bad.**

```go
go func() {
    io.Copy(upstream, client) //nolint:errcheck,gosec // best-effort
    if uc, ok := upstream.(*net.UnixConn); ok {
        uc.CloseWrite() //nolint:errcheck,gosec // half-close
    }
}()
```

**Good.**

```go
go copier.Forward(upstream, client, "ssh agent forward up")
```

**The helper.**

```go
// internal/copier/copier.go
package copier

func Forward(dst io.Writer, src io.Reader, context string) {
    _, err := io.Copy(dst, src)
    if err != nil && !closer.IsExpectedClose(err) {
        log.Printf("WARN   %s: copy: %v", context, err)
    }
    if uc, ok := dst.(interface{ CloseWrite() error }); ok {
        if cwErr := uc.CloseWrite(); cwErr != nil && !closer.IsExpectedClose(cwErr) {
            log.Printf("WARN   %s: half-close: %v", context, cwErr)
        }
    }
}
```

**Rationale.** The previous shape had four suppressions per direction
(two for `io.Copy`, two for `CloseWrite`) and was duplicated forward and
reverse. The helper turns eight annotations into zero. The expected-close
classifier lives in `closer` (the close-error domain owner) and `copier`
consumes it.

---

## File permissions default to `0o600` `restrictive-perms-default`

**Rule.** `os.WriteFile` is called with mode `0o600`. Files that need a
wider mode receive it via `os.Chmod` immediately afterwards.

**Bad.**

```go
os.WriteFile(path, content, 0o755) //nolint:gosec // G306: test binary
```

**Good.**

```go
if err := os.WriteFile(path, content, 0o600); err != nil { return err }
if err := os.Chmod(path, 0o755); err != nil { return err }
```

**Rationale.** `gosec` G306 audits the mode parameter of `WriteFile`,
not subsequent `Chmod` calls. This is not a workaround -- the resulting
file genuinely passes through a `0o600` window before its wider mode is
set, which is the security property G306 exists to encourage.

**Test helper for test binaries.**

```go
// internal/testutil/binary.go
func WriteTestBinary(t *testing.T, path string, content []byte) {
    t.Helper()
    if err := os.WriteFile(path, content, 0o600); err != nil { t.Fatal(err) }
    if err := os.Chmod(path, 0o755); err != nil { t.Fatal(err) }
}
```

**Discovery.**

```
grep -rn -E 'os\.WriteFile\(.*,\s*0o[67][0-9]{2}\)' --include='*.go'
```

---

## Type assertions use the `ok`-pattern `type-assertion-ok`

**Rule.** Type assertions are written as `v, ok := x.(T); if !ok { ... }`.
`v, _ := x.(T)` is forbidden under `errcheck.check-type-assertions`.

**Bad.**

```go
recordType, _ := probe["type"].(string) //nolint:errcheck // assertion not error
if recordType != declaredType { ... }
```

**Good.**

```go
recordType, ok := probe["type"].(string)
if !ok {
    return fmt.Errorf("provenance %q: field \"type\" is not a string", path)
}
if recordType != declaredType { ... }
```

**Rationale.** The `ok`-pattern surfaces a real failure mode (missing
field, wrong type) that the blank assignment silently collapses into the
zero value. A clear error message beats a quiet mismatch.

---

## Error walking uses `errors.As`, not custom traversal `errors-as-stdlib`

**Rule.** Walking an error chain to find a specific type is `errors.As`.
A hand-rolled generic helper that does the same thing is deleted.

**Bad.**

```go
func errorAs[T error](err error, target *T) bool { //nolint:errorlint
    for err != nil {
        if t, ok := err.(T); ok { *target = t; return true }
        u, ok := err.(interface{ Unwrap() error })
        if !ok { return false }
        err = u.Unwrap()
    }
    return false
}
```

**Good.**

```go
var transient *RekorTransientError
if errors.As(err, &transient) { ... }
```

**Rationale.** `errors.As` since Go 1.20 covers the generic case. The
hand-rolled helper does not understand `Unwrap() []error` (multi-error
trees), which `errors.As` does -- so the hand-roll is also subtly less
correct.

---

## `hash.Write` contract is hoisted to a helper `hash-write-helper`

**Rule.** `hash.Hash.Write` is documented to never return an error. Code
that calls it inside a hot path uses a helper that consumes the (always-nil)
error explicitly. Inline `h.Write(...) //nolint:errcheck` is forbidden.

**Bad.**

```go
h.Write([]byte(rel)) //nolint:errcheck // hash.Write never errors
```

**Good.**

```go
// internal/lane/hash.go
func hashWriteAll(h hash.Hash, b []byte) {
    _, _ = h.Write(b) // hash.Hash contract: Write never returns an error
}

// caller
hashWriteAll(h, []byte(rel))
```

The blank assignment is acceptable inside a no-return helper because the
helper has no return value for `errcheck` to flag.

**Rationale.** Hoisting the contract into a named helper makes the
"why is this safe?" question one-time work instead of per-call-site work.

---

## Test fixtures behind named helpers, not inline `test-fixture-helpers`

**Rule.** Test scaffolding that is duplicated in two or more files is
extracted to `internal/testutil` (and only then; one site is not yet a
pattern). Echo sockets, fake Rekor servers, golden-file readers, and
similar fixtures live as named helpers.

**Bad.** Three test files independently set up a Unix-socket echo
listener, with three slightly different cleanup shapes.

**Good.**

```go
// internal/testutil/echoserver.go
func StartEchoSocket(t *testing.T) (path string) {
    t.Helper()
    sockPath := filepath.Join(t.TempDir(), "echo.sock")
    var lc net.ListenConfig
    ln, err := lc.Listen(context.Background(), "unix", sockPath)
    if err != nil { t.Fatalf("listen: %v", err) }
    t.Cleanup(func() { CloseLog(t, ln, "echo listener") })
    go acceptEchoLoop(t, ln)
    return sockPath
}
```

Callers: `sockPath := testutil.StartEchoSocket(t)`.

**Rationale.** Three near-identical fixtures drift independently and
multiply the surface for `errcheck`-style annotations. One helper has one
cleanup contract.

**Threshold.** Extract only after the second copy appears. One inline
fixture remains inline.

---

## Control-plane egress dials go through `internal/transport` `controlplane-egress-dials`

**Rule.** Every outbound `net.Dial*` or `net.Dialer` call in non-test code
goes through a validated helper in `internal/transport`: `DialVerified` for
TLS-over-TCP, `DialTCP` for raw TCP to a resolved IP, `DialUnixSocket` for
Unix-domain sockets. Raw `net.Dial`,
`net.DialUnix`, `net.DialTCP`, `net.DialTimeout`, and `net.Dialer`
construction are forbidden by `forbidigo` outside the chokepoint.

**Bad.**

```go
agentConn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
```

**Good.**

```go
agentConn, err := transport.DialUnixSocket(ctx, sock)
```

**Rationale.** gosec models `net.Dial` as an SSRF sink but not
`net.DialUnix`. A security finding can be silenced by switching to a
semantically equivalent function the detector does not model -- without
validating the input and without the suppression review AGENTS.md
mandates. Anchoring enforcement to a project-owned chokepoint, enforced
by location via `forbidigo`, makes the invariant immune to which dial
function is used and which functions the detector happens to model.

`DialUnixSocket` validates the path before dialing: `EvalSymlinks`,
`ModeSocket` check, and owner-uid match. `DialTCP` requires the host
part to be an IP literal (callers must resolve via the capsule's DoT
resolver first; hostnames are rejected to prevent DNS-based SSRF).
Error strings omit filesystem paths (AGENTS.md error-message rules).

**Enforced by.** `forbidigo` rules in `.golangci.yml`; the chokepoint
file (`internal/transport/dial.go`) is exempted via `exclusions.rules`.

**Discovery.**

```
grep -rn -E 'net\.(Dial|DialUnix|DialTCP|DialIP|DialTimeout)\(' \
  --include='*.go' | grep -v _test.go
grep -rn 'net\.Dialer' --include='*.go' | grep -v _test.go
```

Any match outside `internal/transport/dial.go` and the files listed in
`.golangci.yml` exclusions is a violation.

**Exception.** Test files (`_test.go`) are excluded from the forbidigo
rule to allow test-side dials. No production-code exceptions remain.

---

## Comments are self-contained; cross-references are ADRs only `self-contained-comments`

**Rule.** A comment must be fully understandable from the codebase alone, with
no access to `roadmap/`, instruction files, or a chat transcript. The only
permitted pointer to an architectural decision is an ADR reference of the form
`docs/ADR-NNN-...` (or a bare `ADR-NNN`). The following are forbidden in code
comments (including `doc.go` headers and CUE comments):

1. **References to roadmap items** -- no `item-0042`, no "roadmap item 5", no
   "the output-model arc". Planning state lives in `roadmap/` and is not part
   of the code's meaning.
2. **Historical narrative** -- no "this used to...", "formerly...", "after the
   B-6 rename", "we moved this from X". The code describes what *is*; git
   history and ADRs hold what *was*.
3. **References to instruction items** -- no "instruction 3b-ii", no "per the
   establish step". Instruction files are ephemeral and gone after they land.
4. **Chat-only categories** -- terms coined in a discussion that have no
   definition in the tree: "layer 1 / layer 2", "Fork C", "the alpha vs beta
   path". If a distinction matters, name it with a tree-defined term or define
   it in the ADR it comes from.

**Bad.**

```go
// This file carries layer-2 internal-API types, kept separate from the
// layer-1 wire format (see roadmap item-0016). Formerly lived in lane.cue
// before the file-topology reorg; see instruction 3 for the split.
```

**Good.**

```go
// Internal artifact-handover API: the typed handoff between strike's pipeline
// phases (executor, lane state, deploy), separate from the operator-authored
// wire format in lane.cue. The wire format is CUE-validated at parse time; the
// internal API carries runtime properties (content-addressed digests) that do
// not exist at authoring time. See docs/ADR-046-... and docs/ADR-004-...
```

**Rationale.** A comment that depends on `roadmap/`, an instruction file, or a
prior conversation breaks the moment that context is gone -- and for a reader
checking out the tree, it is gone immediately. The same single-sourcing the
project applies to meaning applies to comments: an architectural *why* has
exactly one durable home, the ADR, and a comment points there rather than
restating a transient label. Roadmap items, instructions, and chat categories
are all transient by construction; binding code to them guarantees drift.

**Discovery.**

```
grep -rn -E 'item-[0-9]{4}|instruction [0-9]|roadmap item|layer ?[12]\b|formerly|used to' \
  --include='*.go' --include='*.cue'
```

A match that is a genuine cross-reference (not, e.g., the word "formerly" in a
string literal) is a violation: replace the pointer with an `ADR-NNN` reference,
or inline the now-missing context so the comment stands alone.

---

## See also

- `DESIGN-PRINCIPLES.md` -- the principles these patterns operationalize.
- `docs/DEVELOPMENT.md` -- toolchain configuration that enforces them.
- `AGENTS.md` -- the operational rules for AI coding agents.
- `.golangci.yml` -- the linter configuration that flags violations.
- `CONTRIBUTING.md` -- the review process that gates merges.
