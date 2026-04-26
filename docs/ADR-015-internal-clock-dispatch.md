# ADR-015: All Time Access Dispatched Through internal/clock

## Status

Accepted.

## Context

The reproducibility principle (ADR-009) requires that values
affecting artifact content bytes come from a deterministic source.
`SOURCE_DATE_EPOCH` is the well-known mechanism: a Unix timestamp
the build environment provides, used as the canonical "now" for any
timestamp that lands in a build output. Without it, every build is
non-reproducible by clock alone.

The naive enforcement is a code-review rule: "do not call
`time.Now()` in artifact-content paths". A grep through the
codebase at one point produced 14 direct `time.Now()` call sites,
some legitimate (event-receipt timestamps, telemetry), some not
(SBOM timestamps, deploy IDs). Distinguishing the legitimate from
the non-legitimate required understanding the data flow at every
call site.

The structural fix is to centralize time access in a single package
and make the question "is this a build value or an event value"
explicit at every call. The package becomes the only place that
imports `"time"`; everything else imports the package.

## Decision

A new package `internal/clock` is the only place in strike permitted
to import the standard-library `time` package. A `depguard` rule
rejects direct `"time"` imports anywhere else, with one exception
for the clock package's own files (`clock.go` and `clock_test.go`).

The package exposes:

- `clock.Wall()` -- current wall-clock time. Use for event
  receipts, audit logs, engine handshakes, test fixtures with
  short validity windows. Do *not* use for values that end up in
  artifact content bytes.
- `clock.Reproducible()` -- the time to stamp into reproducible
  artifact content. Reads `SOURCE_DATE_EPOCH`; defaults to Unix
  epoch zero in UTC when unset or malformed.
- `clock.Since(t)` -- duration since `t`, for telemetry.
- `clock.Unix(sec, nsec)` -- construct a `clock.Time` from Unix
  components; used for parsing external timestamps.
- `clock.ParseDuration(s)` -- parse a duration string; used for
  lane spec fields like step timeouts.
- Type aliases `clock.Time` and `clock.Duration`, equal to
  `time.Time` and `time.Duration`. Aliases (not new types), so
  JSON serialization, interface satisfaction, and reflection
  identity are byte-identical to the underlying types.
- Duration constants (`clock.Second`, `clock.Minute`, etc.) and
  `clock.RFC3339`.

Symbols beyond this surface are not exported. `Date`, calendar
constructors, timer functions, and additional format layouts are
deliberately omitted; they come back through a deliberate ADR
extension if a future caller needs them. Test fixtures that need
fixed calendar timestamps use `clock.Reproducible()` (epoch zero by
default), not a separate `Date` constructor: tests that do not
assert on a specific calendar moment use the same time source as
production.

The split between `Wall` and `Reproducible` puts the reproducibility
boundary at the call site. The question "is this a build value or
an event value" is answered explicitly, once, per call. There is no
per-package convention to remember; the function names carry the
semantics.

## Consequences

- The principle "time access affecting artifact content must come
  from a reproducible source" becomes a CI-checkable invariant
  rather than a code-review convention.
- A new caller that needs current time has to choose between
  `Wall` and `Reproducible`. The choice is the work of one line and
  cannot be silently wrong: each function's doc comment says what
  it is for.
- The audit transport (ADR-014) uses `clock.Wall()` for duration
  measurement; the bootstrap-reproducibility proof (ADR-009) uses
  `clock.Reproducible()` for the SBOM timestamp. The same package
  serves both, with the boundary visible in the function name.
- Future timekeeping needs (e.g. timeouts via `time.NewTimer`,
  formatting via `time.Parse`) come back as deliberate extensions.
  Every additional export crosses the operator's review by the
  stop-and-confirm protocol.
- Dependency injection (a `Clock` interface) is not introduced.
  No current test asserts byte-equality on a value that came from
  `clock.Wall()`; the abstraction would be speculative and would
  violate "Code is liability".

## Principles

- Reproducibility is enforced, not hoped for
- Code is liability (one entry point per semantic, no
  configuration knob, no speculative interface)
- CUE first (where time values appear in schemas, the schema
  enforces the format; the dispatch ensures the value at runtime
  comes from a reviewed source)
