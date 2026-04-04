# Cross-validation test vectors

Self-contained test fixtures for verifying that independent
implementations (Go, Rust) produce identical results for the
same inputs.

## Format

Each JSON file is a test vector with `boundary`, `inputs`, and
`expected` fields. The CUE schema is in `specs/crossval.cue`.

## Boundaries

- **AssembleImage**: OCI image assembly (executor/pack.go)
- **SpecHash**: Step spec hashing (registry/cache.go)
- **SignManifest**: Cosign signing payload (executor/sign.go)
- **ValidateAttestation**: Attestation schema (deploy/validate.go)

## Regenerating vectors

    go test ./internal/executor/ -run Golden -update -count=1

This overwrites the `expected` fields with current Go output.
If a Rust verifier disagrees, the discrepancy is a bug in one
implementation.
