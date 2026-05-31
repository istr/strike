# ADR-037 Implementation Roadmap

## Status: IMPLEMENTED

## What has landed

- **Three-section attestation predicate.** `sealed` / `engine_dependent` /
  `informational` structure in `specs/attestation.cue` and mirrored Go types
  in `internal/deploy/deploy.go`. Commit `5e88f2b`.
- **Engine record D2 split.** `#EngineConnection` (sealed, CP-observed) and
  `#EngineMetadata` (informational, engine self-reported) are separate types.
- **Provenance signature dropped** (Decision B-iii). `#SignatureInfo`,
  `SignatureInfo`, `IsSigned()` removed.
- **Provenance placed under informational.** All four provenance variants
  under `informational.provenance[]`.
- **Theoretical foundation.** `docs/ATTESTATION-SOUNDNESS-AND-
  THE-TRUST-BOUNDARY.md` landed (Instruction 43). SECURITY.md subsection
  added. Commit `2c1bb93`.
- **Envelope signature verification core.** `internal/verify` package
  (commit `eddb14e`): DSSE envelope parsing, payload-type guard, ECDSA P-256
  signature verification over PAE. Returns decoded attestation JSON for
  caller-side trust-layer semantics. Rekor and anchor cross-checks are
  separate concerns for later instructions.
- **README aim-sentence conditionalization.** Qualified with engine-trust
  condition: end-to-end when the engine shares the controller's trust domain,
  best-effort when it does not, linking SECURITY.md.
- **`engine_dependent.peer_attribution` populated.** Phase-2 wiring landed:
  `collectObservedPeers()` / `ingestRecords()` in `internal/deploy/deploy.go`
  populate `sealed.observed_peers` (Layer V) and
  `engine_dependent.peer_attribution` (Layer E) from capsule-observed
  connection records.

## What is NOT yet implemented

### 1. `strike verify` CLI subcommand

The internal verification library exists (`internal/verify`), but
`cmd/strike/main.go` does not yet expose a `verify` subcommand. The CLI
entry point reads the restructured predicate and surfaces the
section-level trust posture:

- `sealed` claims: verified cryptographically (signature, Rekor SET,
  declared-anchor matches, lane-hash binding, digest dereference).
- `engine_dependent` claims: reported with trust caveat, or verified under
  explicit operator-supplied `trust(E)` flag.
- `informational` claims: recorded for operator consumption with explicit
  "no trust claim" statement.

This is the offline-verifiability promise the project has carried since
the beginning.

## References

- `HANDOVER-trust-layer-predicate-restructure.md` -- frozen design handover
- `docs/ADR-037-two-engine-trust-layers.md` -- governing ADR
- `docs/ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md` -- theory
