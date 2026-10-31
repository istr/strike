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
- **Enforcement is structural, not discretionary.** Secret non-leakage
  is a property of the type, enforced by construction rather than by
  caller discipline.

## Amendment 2026-10-31 -- the environment clause names the property it protects (ADR-058 D7)

The decision bullet "strike's own process environment" described the
write path this record removed: before it, secret values were assigned
into strike's environment on their way to a step container. Read since
as an absolute -- strike reads nothing from its environment -- the clause
became unreachable on every hosted forge, where the platform delivers
the token that requests all other tokens through the environment, and
the tree never met it: the builder's identity token has been read from
`SIGSTORE_ID_TOKEN` since keyless signing landed.

[ADR-058](ADR-058-registry-client-identity-workload-token.md) D7 reads
the clause, from this date, as: strike writes nothing into its own
environment and passes nothing through it to a step container; strike
holds no credential that outlives the run; from the environment strike
reads only declared, short-lived, audience-bound per-run tokens or the
platform's capability tokens, under the lifetime bound of ADR-058 D4.
The bullet list in the decision is not rewritten; this section governs
its reading. The successor that removes the delivered secret altogether,
an attested identity from a SPIFFE Workload API, is parked as a
post-beta item.
