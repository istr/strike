# AGENTS.md -- Instructions for AI Coding Agents

Instructions for Claude Code, Copilot, and similar AI coding agents working
on the strike codebase. Read this entire file before making any changes.
"Code is liability" (below) takes precedence over every other instruction
here.

This file is the agent's read-fully contract: it states only what the agent
must internalize at each anchor. Full reference lives in lookup docs cited
inline -- `docs/DEVELOPMENT.md` (security, testing, and style detail),
`docs/CODE-STYLE.md` (named code patterns), `docs/CUE-WORKFLOW.md` (schema
workflow), `DESIGN-PRINCIPLES.md` (the underlying why), and `ARCHITECTURE.md`.

## Code is liability (operational rule)

First rule, because every other rule degrades if it is not followed.
Principle: `DESIGN-PRINCIPLES.md#code-is-liability`. General-purpose models
bias toward producing more code; in a security tool that bias is attack
surface, audit cost, and a candidate failure mode. Counter-measures, on
every task:

1. **Inline before extracting.** No helper, interface, wrapper, or layer
   unless at least two existing call sites benefit. One hypothetical future
   caller is not a justification.
2. **Reuse the standard library.** Do not add a dependency that duplicates
   `std`. The dependency surface is the supply-chain surface.
3. **Prefer deletion to addition.** If a removal also resolves the issue,
   take it. A change that removes more than it adds is the default shape.
4. **Stop and report instead of expanding scope.** A correct but
   out-of-scope improvement is reported as a follow-up candidate, never
   implemented in passing.
5. **Justify additions.** When code must be added, the commit message states
   which alternatives were rejected and why. "It seemed cleaner" is not one.
6. **Resist abstraction for its own sake.** Three similar lines beat a
   premature helper; the codebase is small enough that duplication is
   auditable.

These apply to AI-generated contributions without exception. "Add a helper
that does X" is read first as "do X"; if X needs no helper, none is added.

## Project overview

strike is a rootless, shell-free, container-native CI/CD executor in Go: a
single static binary (~16 MB) that drives podman over its REST API to run
build steps in hardened containers. The codebase is intentionally small and
must stay small.

Module: `github.com/istr/strike`. Go 1.26+.
Build: `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o strike ./cmd/strike`.

## Execution profile

Instruction files carry an "Execution profile" -- a recommended model class
and reasoning depth for the executing session.

- The profile addresses the operator's launch choice. You do not select,
  change, or re-grade it. If you are running, the operator has chosen.
- The profile never modifies the contract. Gates, byte-exact before-snippets,
  out-of-scope lists, and stop-and-report apply identically under every
  profile. "deep" is not a license for initiative; "none" is not an excuse
  for a failed gate.
- Escalate instead of grinding. If execution repeatedly trips gates, or needs
  live debugging beyond applying the written edits, STOP and report that the
  task appears to exceed the profile. A stop-and-escalate is a correct
  outcome; a forced pass is not.
- An instruction with no profile: ask the operator before starting.

## Hard invariants -- never violate these

1. **No subprocess execution.** Never `exec.Command`, `os/exec`, or any
   subprocess spawning, anywhere. All external work -- container execution,
   state capture, kubectl, HTTP probes -- goes through the `container.Engine`
   REST API over the engine socket. There are zero `os/exec` imports. This is
   a security invariant, not a style choice.
2. **No new dependencies without justification.** Copy the needed code (with
   attribution) or implement it. "A little copying is better than a little
   dependency."
3. **No daemons, embedded servers, gRPC, or web UI.** strike runs and exits.
4. **Secrets never appear in logs, error messages, or process arguments.**
   They live in memory and reach step containers via the engine API only.
5. **All external images are digest-pinned.** `image:latest` and `image:v1.0`
   are rejected; only `image@sha256:...` is accepted.
6. **Unsigned OCI images must not be used by network-enabled steps.**
7. **TCP to the engine requires TLS** (TLS 1.3 minimum); unencrypted TCP is
   rejected at startup. Unix sockets are unaffected. TLS env vars under
   "Build and gates" below.
8. **CUE schemas are the single source of truth.** Every structure that
   crosses a package boundary is defined in CUE under `contract/` before it
   is implemented in Go. Go types are generated from CUE or validated against
   it at runtime; there are no untyped `map[string]string` bags for
   structured data. Workflow: `docs/CUE-WORKFLOW.md`.

## Stop and ask the operator

Some changes are architectural: large, hard to reverse, wide-propagating. For
these, STOP, present the change, and wait for explicit approval -- even when
auto-edit is enabled for the session:

- **Any CUE schema change:** adding, removing, or renaming a `#Type` or a
  field; changing a constraint (regex, bounds, optionality, enum); or moving
  types between files or packages. (Doc-comment fixes, typo fixes, and golden
  updates after an already-approved change do not need confirmation.) Detail:
  `docs/CUE-WORKFLOW.md`.
- **Any `//nolint` or `// #nosec`.** Every suppression is a security
  decision. Present the finding, explain why it is a false positive, and
  wait. The annotation must carry the specific rule code and a written
  justification (e.g. `//nolint:gosec // G304: path is from MkdirTemp, not
  user input`). The sanctioned permanent sites are the annotation-chokepoint
  table in `docs/CODE-STYLE.md`; adding any other long-lived annotation needs
  an ADR.
- **Creating a new package under `internal/`.**

This is the "code is liability" rule applied to authoring: these decisions
are made by the operator, not discovered by the agent mid-edit.

## Security guards the agent breaks by default

Full security reference: `docs/DEVELOPMENT.md#1-security` and
`DESIGN-PRINCIPLES.md`. Two guards are restated here because models violate
them reflexively.

**No `os/exec` (invariant 1).** Container work goes through `container.Engine`:

```go
// CORRECT
exitCode, err := engine.ContainerRun(ctx, container.RunOpts{
    Image: "image@sha256:...", Cmd: []string{"build"},
})
// PROHIBITED
cmd := exec.Command("podman", "run", imageRef)   // NEVER
```

**Container args never invoke a shell.** No `/bin/sh -c`, `bash -c`, or any
shell wrapper -- not in lanes, not in test fixtures, not in docs. Assume no
image has a shell; invoke the tool binary directly:

```yaml
# CORRECT
args: [hugo, --gc, --minify, -d, /out/public]
# PROHIBITED
args: [/bin/sh, -c, "mkdir -p /out && cp -r /src /out/tree"]   # NEVER
```

Reproducible time is also load-bearing: never import the stdlib `time`
package directly; use `internal/clock` (`clock.Wall()` for event timestamps,
`clock.Reproducible()` for any bytes that reach artifact content). depguard
rejects direct `time` imports.

## Code style

Full style reference: `docs/DEVELOPMENT.md#3-code-style` plus the named
patterns in `docs/CODE-STYLE.md`. Agent-critical points:

- **ASCII only.** All code, comments, errors, docs, and commit messages are
  printable ASCII (U+0000 to U+007F). Use `--` not em dash, `->` not arrows,
  `"` not curly quotes, "and" not `&`. Enforced by `make lint-ascii`.
- **US English only** ("initialize", "color").
- `gofmt` / `gofumpt`, no deviations. Max function length 80 lines / 50
  statements; max cyclomatic complexity 15 -- reduce with early returns and
  guard clauses.
- **Comments are self-contained:** no roadmap ids, instruction references,
  historical narrative, or chat-only labels ("layer 1 / layer 2"). The one
  durable cross-reference a comment may carry is an ADR (`docs/ADR-NNN-...`).
  Rule and discovery grep: `docs/CODE-STYLE.md#self-contained-comments`.
- **Field ordering** follows `docs/FIELDALIGNMENT.md`; consult it before
  declaring a struct, not after the linter flags it.

## Testing

Full testing reference -- PKI helpers, coverage, integration, fuzz --
`docs/DEVELOPMENT.md#2-testing`. Non-negotiables:

- Table-driven subtests (`t.Run`); pass with `-race`.
- Hermetic: no podman, no network, no registry. `t.TempDir()` for files,
  `t.Helper()` in helpers.
- Test both success and error paths; no assertion-free tests.
- All cryptographic test material (signing keys, TLS certs, CA chains) is
  ephemeral, generated at test time via `crypto`. Never commit key material,
  not even as fixtures.
- Engine tests use TLS with ephemeral PKI (`newTLSTestEngine` /
  `newMTLSTestEngine`); there is no plaintext HTTP fallback.
- Target 100% statement coverage outside generated code; coverage must not
  decrease on a merge.

## Package layout

CLI entry and orchestration is `cmd/strike/main.go` -- long, procedural,
auditable; do not refactor it into a framework.

CUE contracts (single source of truth) live under `contract/`, one CUE
package per directory: `primitive` (scalar constraints), `lane`, `attest`,
`endpoint`, `trustlayers`, `crossval`; runtime embed in `contract/embed.go`.
Generated Go types land in `internal/{lane,primitive,endpoint}/*.gen.go`
(gitignored; never hand-edit). See `docs/CUE-WORKFLOW.md`.

Go packages under `internal/`: bundle, capsule, clock, closer, container,
copier, deploy, egress, endpoint, executor, front, lane, mediator, primitive,
probe, registry, resolver, schema, testutil, transport, verify. All container
operations go through `container.Engine` (`internal/container`). Signing uses
ECDSA P-256 in `internal/executor` (`crypto/rand`, never `math/rand`).

Do not create new `internal/` packages without asking (see "Stop and ask").
Never create `pkg/`, `util/`, `common/`, `helper/`, `models/`, `types/`, or
`interfaces/` packages.

## Build and gates

```sh
make generate   # cue export -> JSON Schema, then gengotypes -> internal/*/*.gen.go
make specs      # CUE -> JSON Schema only
make golden     # update golden fixtures (never run in a way that masks regressions)
make check      # lint + test + vuln + build -- the one pre-commit gate
```

Environment: `CONTAINER_HOST` (engine address, `unix://` or `tcp://`),
`CONTAINER_TLS_CERT` / `CONTAINER_TLS_KEY` (client mTLS for TCP),
`CONTAINER_TLS_CA` (pin CA; system store if unset), `SOURCE_DATE_EPOCH`
(reproducible builds), `STRIKE_AUDIT` (request audit to stderr),
`STRIKE_INTEGRATION=0` (skip integration tests). On the development machine
the engine is always up and reachable through `CONTAINER_HOST`; check
availability only through that socket.

**After every code change**, run `make lint` and fix all findings before
moving on -- do not batch lint fixes at the end. Run this gate before any
build step.

**Before submitting**, run `make check` exactly as written. A green
`make check` with zero warnings and zero findings is the only acceptable
pre-commit state. Phase order is cheap-before-expensive (lint and deadcode,
then tests, then vuln and build); a failing earlier phase is fixed first,
even when it looks unrelated to your change -- it is part of the working
state your change owns. `deadcode -test ./...` must be clean: wire exported
functions in, or do not write them.

## What not to do

- Do not edit generated `*.gen.go` files; run `make generate`.
- Do not add a `go:generate` directive for anything but CUE codegen.
- Do not introduce build tags; `go test ./...` must work plainly.
- Do not use `init()` functions or package-level mutable state.
- Do not add logging frameworks. All output goes through `log.*`; never write
  `os.Stdout` / `os.Stderr` directly. The logger's `fatalWriter` terminates
  the process on write failure -- a broken audit trail is fatal by design.
- Do not refactor `main.go` into a framework; the procedural orchestration is
  intentional and auditable.
- Do not wrap standard-library types without a clear need.
- Do not change a function signature or remove an exported symbol without
  searching the whole module for callers -- `internal/`, `cmd/`, and `test/`
  alike. Integration tests under `test/` are real callers of production APIs:
  the compiler catches a missed production caller, but a missed test caller
  surfaces only when the gate runs. Fix every caller in the same step; prune
  any helper the removal orphans.
- Do not improvise when a before-snippet does not match the tree. A
  whitespace-only difference on a line you are deleting is immaterial: delete
  it and note the divergence. Any other mismatch means the tree has drifted
  -- stop and report.
- Do not alter retained code to satisfy a literal acceptance grep. If a grep
  for a removed symbol still matches because the token legitimately survives
  in a kept path, the criterion is flawed -- report it and leave the code
  alone.
- Do not establish a file's contents through an arbitrary line window
  (`sed -n 'A,Bp'`, `head`, `tail`). An existence or absence claim rests on a
  whole-file search (`grep -n` over the whole file) or a full read, never on
  a slice: a truncated slice looks identical to a complete one, so a wrong
  window turns "I did not see it" into a false "it is not there". A window is
  legitimate only after a search has located the target, and only for
  surrounding context -- prefer `grep -n -C3 PATTERN file`. Rationale and the
  failure that set this rule:
  `AI-WORKFLOW.md#inspect-the-whole-file-never-a-ritual-window`.

## Commit messages

Conventional Commits (`cliff.toml`, git-cliff). Format
`<type>(<scope>): <description>`: first line imperative, at most 72
characters, no period. Types: `feat fix refactor perf test doc style chore ci
revert`. Scope is encouraged when the change is single-area
(`fix(container): ...`). Breaking changes add `!` after type/scope and
explain in the body. Detail and examples:
`docs/DEVELOPMENT.md#6-commit-messages`.

## When a gate fails: diagnose, never assign blame

A failing check -- one test, a whole suite, a lint rule, a vuln finding, a
build -- is a signal to diagnose, not a verdict to defend against. The
RLHF-trained reflex to ask "was my change at fault?" and stop at the first
plausible external cause is actively harmful: it substitutes a blame verdict
for a diagnosis and leaves the defect in the tree.

1. **Blame is irrelevant; spend zero reasoning on it.** Yours, a
   predecessor's, or no commit's at all -- none of it changes what happens
   next. The failure is part of the working state you own; it gets diagnosed.
2. **Never locate the cause outside the work.** Three forbidden stopping
   points: the environment ("podman is not running" -- unit tests need no
   podman, and the dev engine is always up via `CONTAINER_HOST`, so an
   environment excuse is almost always a misread test); other commits
   ("pre-existing" is a still-open defect you now own); and an unexpected
   in-tree file (a file in the tree is part of the contract -- your model was
   incomplete, the file is not at fault).
3. **Diagnose in a fixed order, every time:** re-read the relevant
   doc/spec/ADR/schema; re-read the existing code the failure touches; re-read
   your own change. The order grounds the diagnosis in declared intent and the
   existing contract before it reaches your edit.
4. **Never shrink the gate to make it pass.** No package selector, `-run`
   filter, build tag, `t.Skip`, `-short`, pipe to `true`, or swallowed exit
   code. A gate that is green only because its scope was cut has been
   disabled, not passed. If the full gate cannot pass, that is the finding to
   report.
5. **The verbatim gate is `make check`**, run exactly as written.
