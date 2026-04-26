# ADR-014: Audit Transport for Forensic Accountability

## Status

Accepted.

## Context

The controller drives the container engine over HTTP through a Unix
socket or TLS-secured TCP. Every operation strike performs (creating
containers, mounting volumes, fetching images, capturing state) is an
HTTP request. In incident response, the question "what did strike
ask the engine to do, and when" is the first question. Without
request-level audit logs, the answer is "look at podman's logs and
correlate". With them, it is "grep the audit stream".

The cost is small: one log line per request with method, path,
status, and duration. The risk is the temptation to log too much.
Container-create requests carry secrets in the request body (env
vars passed to step containers per ADR-006). Logging request bodies
would defeat the typed-secret discipline.

The mechanism is also the place where a previously latent
vulnerability could surface: log lines that include user-influenced
content (URL paths from arbitrary deploy targets, error messages
echoed back from the engine) can carry control characters. Audit
logs are intended for machine consumption; control-character
injection in the log stream is a structurally fixable class of
problem.

## Decision

A `RoundTripper` wrapper called `auditTransport` is registered when
the environment variable `STRIKE_AUDIT` is set (any non-empty value).
It logs every engine request with:

- method (`GET`, `POST`, etc.);
- request path (e.g. `/v5.0.0/libpod/containers/create`);
- response status code (or `-1` if the request failed before a
  response);
- duration rounded to milliseconds.

Bodies are never logged. Headers are not logged. Query parameters
are part of the path and are logged as-is (in libpod, query
parameters carry no secrets).

The wrapper sits *outside* the TLS configuration: it sees plaintext
HTTP after TLS termination on the client side, but it does not see
content that was never decrypted. It uses `clock.Wall()` for
duration (per ADR-015), not `time.Now()` directly, even though the
duration is wall-clock telemetry rather than artifact content.

The audit log uses `log.Printf` to stderr. It is not structured
JSON; the goal is forensic accessibility, not machine ingestion. A
team that wants structured audit can grep the line format, which is
stable.

`STRIKE_AUDIT` is opt-in. The default is no audit log, because the
logs are noisy and filling stderr with engine RPCs degrades the
useful output during normal use. In CI, in production, and during
incident response, operators turn it on.

## Consequences

- A complete record of engine interactions is one environment
  variable away. Investigation of "what happened during this
  deploy" reduces to reading the audit stream.
- The audit log does not capture engine *responses* beyond status
  codes. To reproduce engine behavior, the audit log identifies
  *which* requests to replay; the responses come from the engine
  itself in a fresh investigation.
- Log lines containing user-influenced content (deploy target
  names ending up in URL paths) are a known surface. The current
  implementation accepts this risk because the URL path comes from
  validated lane data, not from arbitrary network input. A future
  hardening could quote the path with `strconv.Quote` to make
  log-injection structurally impossible; this is a candidate for a
  follow-up but not a blocker.
- The audit transport is composable: it sits inside the standard
  `http.Client` chain and works with any transport configuration
  (Unix socket, TLS, mTLS) without case-by-case wiring.

## Principles

- Runtime is attested (audit logs are the runtime equivalent of
  attestation: a record of what happened, not just what was
  produced)
- Secrets are typed (request bodies are never logged because the
  secrets that flow through them are not stringified to log output)
- Code is liability (one wrapper, one log format, no abstraction
  for "audit framework")
