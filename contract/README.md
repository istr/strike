# contract/ -- Cross-Implementation Specification Contract

This directory holds the machine-readable specifications that define
strike's data formats. Any implementation (Go primary, Rust verifier,
external audit tools) must conform to them.

## Source of truth: CUE schemas

Strike uses [CUE](https://cuelang.org) as the single definition language for
both input and output formats. The contract is one CUE package per directory;
the runtime embeds the validation roots plus their import closure (`embed.go`)
and validates against them -- lane input before execution, attestation output
before persistence. The embedded set deliberately excludes `output`, which is
codegen-only: its Go types are generated from CUE, but nothing loads or
validates against it at runtime.

| Package | Holds |
|---------|-------|
| `primitive`   | Irreducible scalar vocabulary: content-addressed digests, identifiers, hashes |
| `endpoint`    | Host/address, TLS-trust, HTTPS-endpoint, and engine-connection identity types |
| `output`      | Runtime output handles |
| `provenance`  | Source-fetch provenance records (git, tarball, OCI, URL) |
| `target`      | Deploy destination |
| `record`      | Artifact and SBOM provenance records |
| `lane`        | Operator-authored input wire format: the `#Lane` tree, network peers, trust-root replica |
| `attest`      | Deploy attestation collect-model (`#Attestation`), published predicates, and the sigstore `#Bundle` |
| `trustlayers` | Trust-layer classification map (governance data) |
| `crossval`    | Cross-validation vector schema |

`endpoint`, `output`, `provenance`, `target`, and `record` are the concept tier:
composed value types that depend only on `primitive`. See
`../docs/SPEC-PACKAGE-LAYERING.md` for the package layout and dependency
direction, and `../docs/ADR-048-contract-type-semantics.md` for the type
semantics.

## Two attestation shapes: internal vs published

Strike keeps two distinct attestation representations:

- **Internal collect-model -- `attest/attestation.cue` (`#Attestation`).** The record strike assembles as a deploy step runs (produce-then-collect, ADR-039), validated at runtime. It sorts every recorded fact into one of three trust layers: `sealed` (sound to any verifier), `engineDependent` (sound only under engine trust), and `informational` (no trust claim).
- **Published predicates -- `attest/predicate.cue`.** At sign time, the internal model is projected into standard-ecosystem in-toto Statements that strike signs and publishes (ADR-040 D3): the `sealed` layer becomes a standard **SLSA Provenance v1** statement, the `engineDependent` layer a strike-defined engine-context predicate, and the `informational` layer a strike-defined informational predicate. Each is signed as its own referrer; Rekor inclusion rides in the Sigstore bundle, never in a predicate payload (ADR-013).

In short: `attest/attestation.cue` is what strike builds and validates internally; `attest/predicate.cue` is what consumers verify.

## Exported formats

For consumers that don't have a CUE runtime, schemas can be exported:

```bash
make specs    # exports JSON Schema to contract/
```

This produces:

- `contract/lane.schema.json` -- JSON Schema for lane.yaml (after YAML -> JSON)
- `contract/attestation.schema.json` -- JSON Schema for deploy attestations
- `contract/trust-layers.json` -- the trust-layer classification map

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

## Using the schemas for a Rust verifier

A Rust verification implementation would:

1. Parse `contract/lane.schema.json` with the `jsonschema` crate
2. Parse `contract/attestation.schema.json` for attestation validation
3. Load golden fixtures from `testdata/golden/`
4. Implement signing, assembly, and digest computation
5. Assert identical outputs for identical inputs

The conformance test suite runs both implementations against the same
golden fixtures and compares outputs. See `../ARCHITECTURE.md` for the
trust boundary diagram.
