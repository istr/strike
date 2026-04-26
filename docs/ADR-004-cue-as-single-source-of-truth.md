# ADR-004: CUE Schemas as the Single Source of Truth for Data Contracts

## Status

Accepted.

## Context

Internal data contracts in a Go-only codebase typically live in
hand-written struct types, with optional JSON Schema or Protocol
Buffers for external interop. This produces three failure modes:

- *Schema drift.* The struct says one thing, the YAML parser allows
  another, the JSON output emits a third.
- *Implicit contracts.* Field requirements ("must be lowercase",
  "must match this regex", "must be one of these values") live in
  validation code scattered across packages, not in the type itself.
- *No second-implementation path.* Cross-implementation verification
  (a Rust verifier checking strike's outputs) requires a portable
  schema definition that does not live in Go code.

CUE solves all three: it defines a constraint language that compiles
to JSON Schema for external consumers, generates Go types for the
primary implementation, and validates inputs and outputs at runtime
against the same definition the types came from.

## Decision

All data contracts that cross a package boundary or appear in
serialized form (lane YAML, deploy attestation JSON, cross-validation
fixtures) are defined in CUE first. Go types are generated from CUE,
not hand-written; YAML inputs and JSON outputs are validated against
the same schemas that generate the types.

CUE schemas are embedded in the strike binary via `//go:embed` and
re-used at runtime for input validation (lane YAML before execution)
and output validation (attestation JSON before persistence and
signing). Hand-written `map[string]string` or `interface{}` for
structured cross-package data is prohibited.

Schema changes follow the stop-and-confirm protocol: any change to
CUE definitions stops AI agents and requires explicit operator
confirmation before code is written.

## Consequences

- Adding a new data contract requires authoring CUE first, getting
  it approved, and then regenerating Go types. The order is not
  optional.
- Field validation (regexes, enums, ranges, conditional fields) lives
  in CUE and is enforced uniformly at parse time, not scattered
  across Go validation functions.
- A Rust verifier (or any other secondary implementation) consumes
  exported JSON Schema and golden test vectors from `test/crossval/`,
  with no need to read Go code.
- Schema migration is hard by design: pre-beta, breaking changes are
  acceptable; once stable, the CUE schema becomes the contract that
  all implementations must agree on.
- The cost is the round-trip CUE -> generated Go -> recompile, which
  is paid once per schema change and produces a structural guarantee
  in return.

## Principles

- Declarative type enforcement (CUE first)
- Code is liability (validation is declarative, not imperative)
