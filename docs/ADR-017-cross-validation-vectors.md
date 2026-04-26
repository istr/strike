# ADR-017: Cross-Validation Through Golden Vectors and JSON Schema Export

## Status

Accepted.

## Context

ADR-004 established CUE as the single source of truth for data
contracts. CUE produces Go types for the primary implementation and
JSON Schema for external consumers. What it does not produce is
*evidence* that an external consumer's interpretation matches
strike's. A second implementation -- a Rust verifier, a policy
engine, an audit tool -- can claim to validate strike attestations,
but without a shared reference, "claim to validate" and "validate
the same things strike validates" are different statements.

The gap is not theoretical. JSON Schema does not capture every
constraint a CUE definition expresses; cross-implementation
disagreements about edge cases (empty fields, null vs absent,
ordering of map keys) emerge in practice. A schema-only contract
also says nothing about *operations* that are not pure validation:
hashing the spec to compute a cache key, signing a payload to
produce a DSSE envelope, assembling an OCI image deterministically
from a base and a layer set. These are byte-level operations whose
correctness is observable but whose specification is hard to write
in pure schema form.

The standard remedy in cryptographic interoperability is
*test vectors*: small, self-contained fixtures of (input, expected
output) pairs that any implementation must reproduce byte-for-byte.
NIST publishes them for cryptographic primitives. The TUF spec
publishes them for client implementations. They are the bridge
between specification text and conformance.

## Decision

strike maintains two cross-implementation contracts side by side:

- **JSON Schema export.** `make specs` exports CUE definitions to
  `specs/lane.schema.json` and `specs/attestation.schema.json`. A
  consumer with a JSON Schema validator (and no CUE runtime) reads
  these and validates strike outputs.
- **Golden test vectors.** `test/crossval/` contains JSON files,
  organized by *boundary* (the operation being tested), with three
  fields each: `boundary`, `inputs`, `expected`. The Go primary
  implementation produces them with `go test -run Golden -update`;
  any second implementation must reproduce them byte-for-byte.

Four boundaries are covered as of this ADR:

- `AssembleImage`: OCI image assembly (base + layer set produces a
  manifest digest).
- `SpecHash`: step-spec hashing for cache keys (args + env + input
  hashes produces a SHA-256 digest).
- `SignManifest` and `SignAttestation`: cosign-compatible signing
  (key + payload produces a signature whose payload is byte-for-byte
  reproducible).
- `ValidateAttestation`: schema validation of attestation JSON
  against the embedded CUE schema.

Vectors live in `test/crossval/<boundary>/<case>.json`, not
`testdata/`, because they are language-independent specification
fixtures consumed by both the Go test suite and any future
secondary implementation. The `testdata/` convention applies only
to fixtures that are part of a single Go package's test scope; the
crossval fixtures cross that boundary.

The `expected` field is regenerated from the Go implementation. If
a second implementation disagrees with a vector, the discrepancy is
a bug in one implementation; resolving it produces a more precise
specification (either the CUE schema, the Go code, or the second
implementation changes), and the vector is updated accordingly.
The vectors are therefore not frozen ground truth -- they are the
working agreement between implementations.

Cryptographic test material in vectors is *parametrized*, not
embedded. A `SignManifest` vector references a `key_pem` field
that is injected at test time from an ephemeral key (per ADR-018).
The `expected.verify.public_key_der_base64` field is derived from
the same ephemeral key. The vector itself contains no private key
material.

## Consequences

- A Rust verifier can be built against `specs/*.schema.json` for
  validation logic and `test/crossval/*` for byte-level operation
  conformance, without reading Go code.
- The CUE schema, the JSON Schema export, and the golden vectors
  must remain consistent. CI runs `make specs && make golden &&
  go test ./...`; any disagreement between layers fails the build.
- Adding a new boundary is a deliberate two-step process: define
  the vector schema in `specs/crossval.cue` (so vectors are
  themselves CUE-validated), then add cases under
  `test/crossval/<boundary>/`. The golden generator emits the
  expected fields; the operator reviews the diff before commit.
- The schema-export path (CUE -> JSON Schema) is lossy for some
  CUE features (disjunctions over types, validation expressions
  that JSON Schema cannot represent). Vectors close this gap by
  fixing concrete examples; where vectors and schema disagree on
  what is valid, the operator picks the canonical answer and one
  of the two is corrected.
- The contract is *executable*, not narrative. Documentation of
  strike's data model can become stale; vectors that fail are
  caught by CI on the next run.

## Principles

- CUE first (schema is the source; vectors are the conformance
  evidence)
- Reproducibility is enforced (vectors test byte-equality, not
  semantic equivalence)
- Code is liability (vectors are JSON files, not a custom test
  harness)
- External references are digest-pinned (vector inputs use
  content-addressed digests; vector outputs are deterministic
  hashes)
