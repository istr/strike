# ADR-006: Secrets Are a Typed Primitive, Not a String

## Status

Accepted.

## Context

The default representation of a secret in most codebases is `string`
or `[]byte`. This makes leakage a discipline of the caller: every
log line, every error message, every JSON serialization, every
environment-variable assignment is a potential exfiltration point that
relies on the author remembering to redact. The number of such points
in a non-trivial codebase is large and grows with every change.

The alternative is to make leakage a property of the type. A secret
type that prints redacted, marshals redacted, errors redacted, and is
unreachable as a raw string from outside its package eliminates the
class of mistakes where a developer forgot to obscure something. The
discipline shifts from "remember to redact at every callsite" to
"remember not to introduce a method that exposes the raw value", and
the latter is enforceable by review of one file rather than every
file.

## Decision

Secret values in strike are carried in a dedicated type. Every method
that could expose the value -- `String()`, `MarshalJSON()`, `Format()`,
implicit `%v`/`%s` printing, error wrapping -- returns a redacted
placeholder. The raw value is reachable only through a single,
explicitly-named accessor used by the engine API request body
constructor.

Secrets live only in process memory. They are passed to step
containers via the engine API's container-create request body (HTTP
POST to a Unix socket). They never appear in:

- strike's own process environment;
- step process arguments;
- log output, including error chains;
- on-disk artifacts produced by strike.

## Consequences

- Adding a new code path that handles secrets does not require
  remembering to redact: the type does it.
- Tests assert that `fmt.Sprintf("%v", secret)` and `%s`, JSON
  serialization, and error wrapping all return the redacted form.
- Refactors that move secrets between packages cannot accidentally
  expose them through a new logging or serialization path, because
  the new path also goes through the redacting type.
- The single accessor is reviewable: any change that adds a second
  raw-value accessor is a deliberate weakening of the contract and
  visible in a single file's diff.
- Test fixtures use ephemeral secrets generated at test time. No
  secrets are committed.

## Principles

- Secrets are typed
- Code is liability (redaction is structural, not procedural)
