# ADR-037 Implementation Roadmap

## Status: SUBSTANTIALLY IMPLEMENTED

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
- **engine_dependent empty by structural design.** Phase-1 honest posture;
  struct-literal `{}`.
- **Theoretical foundation.** `docs/foundation/ATTESTATION-SOUNDNESS-AND-
  THE-TRUST-BOUNDARY.md` landed (Instruction 43). SECURITY.md subsection
  added. Commit `2c1bb93`.

## What is NOT yet implemented

### 1. `strike verify` subcommand (Instruction 45)

Does not yet exist. The verifier reads the restructured predicate and
surfaces the section-level trust posture:

- `sealed` claims: verified cryptographically (signature, Rekor SET,
  declared-anchor matches, lane-hash binding, digest dereference).
- `engine_dependent` claims: reported as "empty in Phase 1" (honest
  best-effort) or verified under explicit operator-supplied `trust(E)` flag.
- `informational` claims: recorded for operator consumption with explicit
  "no trust claim" statement.

This is the offline-verifiability promise the project has carried since
the beginning. Green-field implementation against the restructured predicate.

### 2. README aim-sentence conditionalization (Instruction 46)

The README currently says "end-to-end software attestation and provenance
tracing" without the conditional. The foundation note requires qualifying
that under remote/untrusted engines, strike is best-effort. Small docs-only
change.

### 3. Phase-2 capsule-observed engine-action attribution

Populates `engine_dependent` with per-peer connection routing records per
ADR-038 Phase 2. Schema-additive on the new shape. Depends on ADR-038's
capsule restructure landing first.

## Sequencing

1. `strike verify` (Instruction 45) -- immediate next item
2. README conditionalization (Instruction 46 or fold into 45)
3. Phase-2 capsule attribution -- downstream of ADR-038 implementation

## References

- `HANDOVER-trust-layer-predicate-restructure.md` -- frozen design handover
- `docs/ADR-037-two-engine-trust-layers.md` -- governing ADR
- `docs/foundation/ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md` -- theory
