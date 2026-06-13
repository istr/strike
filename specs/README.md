# specs/ -- Cross-Implementation Specification Contract

This directory holds the machine-readable specifications that define
strike's data formats. Any implementation (Go primary, Rust verifier,
external audit tools) must conform to these specs.

## Source of truth: CUE schemas

Strike uses [CUE](https://cuelang.org) as the single definition language
for both input and output formats:

| Schema                | Location                       | Validates                     |
|-----------------------|--------------------------------|-------------------------------|
| Lane definition       | `specs/lane.cue`               | YAML input (lane.yaml)        |
| Deploy attestation (internal) | `specs/attestation.cue`        | Internal collect-model, validated at runtime |
| Artifact provenance   | `specs/artifact.cue`           | Artifact signing records      |
| Source provenance     | `specs/source-provenance.cue`  | Git provenance records        |
| Cross-val vectors     | `specs/crossval.cue`           | Cross-validation test vectors |
| Published predicates  | `specs/predicate.cue`          | Signed in-toto / SLSA statements (the published output) |
| Transport & trust     | `specs/transport.cue`          | Shared host, TLS-trust, DoT-resolver, and HTTPS-endpoint types |
| Sigstore trust root   | `specs/sigstore-trustroot.cue` | TrustedRoot replica (keyless verification anchor) |
| Sigstore bundle       | `specs/sigstore-bundle.cue`    | Published bundle (v0.3) emission contract, validated at sign time |

CUE schemas are embedded in the Go binary via `//go:embed` and validated
at runtime -- lane input before execution, attestation output before
persistence.

## Two attestation shapes: internal vs published

Strike keeps two distinct attestation representations:

- **Internal collect-model -- `attestation.cue` (`#Attestation`).** The record strike assembles as a deploy step runs (produce-then-collect, ADR-039), validated at runtime. It sorts every recorded fact into one of three trust layers: `sealed` (sound to any verifier), `engineDependent` (sound only under engine trust), and `informational` (no trust claim).
- **Published predicates -- `predicate.cue`.** At sign time, the internal model is projected into standard-ecosystem in-toto Statements that strike signs and publishes (ADR-040 D3): the `sealed` layer becomes a standard **SLSA Provenance v1** statement, the `engineDependent` layer a strike-defined engine-context predicate, and the `informational` layer a strike-defined informational predicate. Each is signed as its own referrer; Rekor inclusion rides in the Sigstore bundle, never in a predicate payload (ADR-013).

In short: `attestation.cue` is what strike builds and validates internally; `predicate.cue` is what consumers verify.

## Exported formats

For consumers that don't have a CUE runtime, schemas can be exported:

```bash
make specs    # exports JSON Schema to specs/
```

This produces:

- `specs/lane.schema.json` -- JSON Schema for lane.yaml (after YAML -> JSON)
- `specs/attestation.schema.json` -- JSON Schema for deploy attestations

## Golden test fixtures

Deterministic test vectors live in `internal/executor/testdata/golden/`.
These are the cross-validation anchors: given identical inputs, any
implementation must produce outputs matching these fixtures.

Generate/update golden files:

```bash
go test ./internal/executor/ -run Golden -update
```

Fixtures include:

| Fixture | Input | Output | Cross-validation target |
|---------|-------|--------|------------------------|
| `sign_manifest.json` | fixed key + digest | signature + payload | ECDSA P-256 signing |
| `assemble_image.json` | empty base + file layer | manifest digest | OCI image assembly |
| `cache_key.txt` | step args + env + inputs | SHA-256 cache key | Digest computation |

## Using specs for a Rust verifier

A Rust verification implementation would:

1. Parse `specs/lane.schema.json` with the `jsonschema` crate
2. Parse `specs/attestation.schema.json` for attestation validation
3. Load golden fixtures from `testdata/golden/`
4. Implement signing, assembly, and digest computation
5. Assert identical outputs for identical inputs

The conformance test suite runs both implementations against the same
golden fixtures and compares outputs. See `ARCHITECTURE.md` for the
trust boundary diagram.
