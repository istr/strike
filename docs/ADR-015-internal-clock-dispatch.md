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

## Amendment 2026-11-17 -- `clock.Reproducible` rejects a malformed `SOURCE_DATE_EPOCH` (ADR-059 D7)

The Decision gives `clock.Reproducible()` one answer for two cases: the
epoch when `SOURCE_DATE_EPOCH` is unset, and the epoch when it is
malformed. A mistyped value was thereby indistinguishable from none, and
the run went on to stamp 1970 into what it published.
[ADR-059](ADR-059-sbom-sealed-digest-and-signed-statement.md) D7 rules
that no malformed value becomes the epoch. From this date:

- `clock.Reproducible()` returns a time and an error. An unset or empty
  `SOURCE_DATE_EPOCH` is the Unix epoch in UTC, as before. A set value
  is valid when it is written as `date +%s` prints it, in decimal digits
  without sign or leading zero, the form the SOURCE_DATE_EPOCH
  specification requires, and counts from 0 to 253402300799 seconds
  (9999-12-31T23:59:59Z): non-negative and within the range of RFC 3339,
  as ADR-059 D7 rules. Every other value is an error.
- `strike run` calls it before it reads the lane, so a malformed value
  fails the run before any step starts and any deploy pushes. The one
  consumer, the timestamp of an SBOM document, calls it again and cannot
  ignore the error. No value is carried from the first call to the
  second.
- A test fixture that needs a fixed timestamp uses
  `clock.Unix(0, 0).UTC()` and no longer reads the environment of the
  test process.

The surface of the package gains no symbol.

**Supersedes, in the Decision above:** "defaults to Unix epoch zero in
UTC when unset or malformed" is read as: "is Unix epoch zero in UTC when
unset or empty, and an error when malformed"; "Test fixtures that need
fixed calendar timestamps use `clock.Reproducible()` (epoch zero by
default), not a separate `Date` constructor: tests that do not assert on
a specific calendar moment use the same time source as production." is
read as: "Test fixtures that need a fixed timestamp use
`clock.Unix(0, 0).UTC()`, not a separate `Date` constructor."

## Amendment 2026-11-20 -- a set but empty `SOURCE_DATE_EPOCH` is malformed (ADR-049)

The amendment of 2026-11-17 reads an unset and an empty
`SOURCE_DATE_EPOCH` alike, as the Unix epoch. An empty value is a set
value, and the SOURCE_DATE_EPOCH specification requires a set value to be
the ASCII representation of an integer, which the empty string is not.
Rule (1) of [ADR-049](ADR-049-type-discipline-internal-seams.md), as
amended on 2026-11-20, has the owning parser reject a set but empty
value. From this date an unset `SOURCE_DATE_EPOCH` is the Unix epoch in
UTC, and a set but empty one is an error like every other malformed
value. A run that wants the epoch leaves the variable unset or sets it to
`0`. The surface of the package gains no symbol.

**Supersedes, in the amendment of 2026-11-17 above:** "An unset or empty
`SOURCE_DATE_EPOCH` is the Unix epoch in UTC, as before." is read as: "An
unset `SOURCE_DATE_EPOCH` is the Unix epoch in UTC, as before; a set but
empty one is malformed."; and "is Unix epoch zero in UTC when unset or
empty, and an error when malformed" is read as: "is Unix epoch zero in
UTC when unset, and an error when set but empty or malformed".
