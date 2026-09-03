# Cross-validation test vectors

Self-contained test fixtures for verifying that independent
implementations (Go, Rust) produce identical results for the
same inputs.

These vectors live in `test/crossval/` (not `testdata/`) because they
are language-independent specification fixtures consumed by both
Go tests and the future Rust verifier.

## Format

Each JSON file is a test vector with `boundary`, `inputs`, and
`expected` fields. The CUE schema is in `contract/crossval/crossval.cue`.

## Boundaries

- **AssembleImage**: OCI image assembly (executor/pack.go)
- **SpecHash**: Step spec hashing (registry/cache.go)
- **ValidateAttestation**: Attestation schema (deploy/validate.go)
- **StateDigest**: Deploy state capture digest (deploy/digest_state.go)
- **RenderKnownHosts**: Container ssh_known_hosts rendering
  (executor/sshknownhosts.go)

## What a vector asserts

Every input a boundary reads is in the vector, stated in wire terms: a
second implementation constructs from it rather than naming a library
artifact. The `expected` block is normative -- every conforming
implementation reproduces it byte for byte.

`AssembleImage` additionally carries a `go_ggcr_reference` block that is
**not** normative. The layer digest inside an OCI manifest covers a
gzip-compressed blob, and DEFLATE output is not specified by compression
level, so no independent implementation reproduces the manifest digest.
Those values pin the reference implementation against its own regression
and nothing more; see ADR-046.

## Regenerating vectors

    go test ./internal/executor/ -run Golden -update -count=1

This overwrites the `expected` fields with current Go output, for the
boundaries whose runners live in `internal/executor`. The `state_digest`
and `attestation` vectors are exercised from `internal/deploy` and their
expectations are hand-maintained.

A regenerated block's keys come back in the Go struct's field order, so
the diff may reorder keys without changing a value. If a Rust verifier
disagrees on a *value*, the discrepancy is a bug in one implementation.
