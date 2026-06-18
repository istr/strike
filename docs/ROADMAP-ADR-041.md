# ADR-041 Implementation Roadmap

## Status: COMPLETE (verify arc landed; instructions 1--3 done)

No residual: the CLI trust-root override is a digest-pinned image ref
(`--trust-root-ref`, `669eca89`), so the verify path reads no host-local file and
the anchor is always lane bytes or a digest-pinned image. Base-SBOM signature
verification (ROADMAP-ADR-040 instruction 2c) has landed; the v1-verifier
teardown is complete.

ADR-041 is Accepted: the decision record is at
`docs/ADR-041-lane-as-verification-policy.md`, registered in
`docs/ADR-INDEX.md` by number.

The foundation is in place: ADR-040 instruction 5's core verify layers are
complete in `internal/verify`, tested end-to-end with golden fixtures and
live tests against the sigstore-local harness. Lane-digest computation and
enforcement have been implemented in the producer path (commit 4cfdbfe). The
verify core is now wrapped in the CLI and bound to lane policy (identity,
issuer, trust root), exposing both verification use cases -- UC1 (consumer,
explicit parameters) and UC2 (operator, lane as policy) -- with per-layer
predicate validation and V/E trust-mode gating (instruction 3).

## What has landed

- **ADR-041 plumbing.** Decision record placed, indexed, cross-referenced.
  Status flipped to Accepted.
- **Verify core (from ADR-040 instruction 5a).** `internal/verify` package
  fully implements bundle verification in independent fail-closed layers:
  bundle shape, trusted time, leaf certificate chain and identity binding,
  DSSE signature, and Rekor v2 transparency-log inclusion. `Verifier` type
  holds the trusted material and signer identity; `Verify()` returns the
  verified payload or a layer sentinel error.
- **Lane-digest computation (D5, partial).** `lane.Parse()` computes the
  sha256 digest of the input bytes at parse time; the digest is sealed
  (Layer V) in the attestation's `lane_digest` field. This binds the lane
  to its attestations and enables version-sharp verification.
- **Identity enforcement (D5, partial).** The deploy path (producer) enforces
  that the ambient OIDC token's subject equals the lane-declared identity
  before Fulcio contact (commit 4cfdbfe). The check is fail-closed: token
  mismatch aborts the deploy.
- **Golden fixtures and live tests (from ADR-040 instruction 5a).** End-to-end
  verification tested with:
  - Golden bundles (known-good sigstore v0.3 bundles verified offline)
  - Live chain exercises (producer and verifier against the sigstore-local
    harness, no replay)
  - Differential tests (layer failures caught when expected)

## What is NOT yet implemented

Grounded against the current snapshot.

### D1 -- CLI subcommand exposure (LANDED)

The `strike verify` subcommand is wired (UC1 and UC2), reading bundles via
referrers, resolving the trust root, and running the keyless verify per bundle
plus a subject-digest check. The lane-digest binding and per-layer predicate
validation remain (D4 / instruction 3). It exposes the two use cases:
- UC1: `strike verify --identity=<id> --issuer=<iss> --trust-root-ref=<root-image@digest> <digest>`
- UC2: `strike verify --lane=<lane.yaml> <digest>` (identity, issuer, root from lane)

### D2 -- Lane truth source for policy

The lane's declared identity, issuer, and keyless endpoints are not yet
consumed by the verify path. When integrated, UC2 verification will source
these directly from the lane file without re-typing.

### D3 -- Trust root sourcing and override

The trust-root is currently embedded in UC1 tests as a fixture. The lane
will declare signature roots (digest-pinned by reference) and UC2 will
consume them; UC1 accepts an explicit override (--trust-root-ref flag, a digest-pinned image). The
TLS transport anchors (`#TLSTrust` on keyless endpoints) are producer
concerns; the signature roots (Fulcio CA, Rekor keys, TSA cert) are
consumer concerns, and they must be declared separately.

### D4 -- Predicate validation and trust-mode gating (LANDED)

ADR-040 D3 defines three predicate layers: sealed (V), engine-dependent (E),
and informational. `strike verify` now classifies each fetched bundle by layer
and gates the exit on the V/E model: a Layer-V (sealed) failure or absence is a
hard fail with no opt-out; a Layer-E (engine-context) failure or absence is a
hard fail unless `--no-engine-trust` degrades it to informational; the
informational layer never gates. Per-layer validation enforces the
predicateType and the sealed laneDigest (present always; equal to the policy
lane in UC2). Deep schema conformance (full SLSA Provenance v1 schema, SBOM
format compliance) and base-SBOM signature verification remain deferred.

## Instruction-file sequence

CUE-first for lane schema extensions; then implementation. Each item is its
own instruction file under the established conventions.

### 1. Lane schema and verify subcommand -- LANDED

**1a. (LANDED)** Trust-root sourcing in the lane keyless config:
- `trustRootRef`: digest-pinned reference, fetched by OCI descriptor
  (`registry.FetchTrustRoot`) and digest-verified.
- `trustRoot`: inline TrustedRoot replica (testing and emergency override).
- Resolution order in `internal/verify.ResolveTrustedMaterial`: explicit
  `--trust-root-ref` image, else inline `trustRoot`, else `trustRootRef`, else
  fail-closed `ErrNoTrustRoot`. The single-bundle model superseded the sketched
  per-endpoint override (fulcio_root / rekor_keys / tsa_root); that idea is not
  adopted.

**1b. (LANDED)** The keyless config carries the optional trust root (UC2 default;
UC1 explicit override via `--trust-root-ref`, a digest-pinned image). Empty means
fail-closed (`ErrNoTrustRoot`) -- the intended terminal, not a gap: the anchor is
operator-chosen and never derived from the verified artifact (ADR-041
Principles).

**1c.** (LANDED) Expose `strike verify` subcommand in `cmd/strike`:
- UC1: `strike verify --identity=<id> --issuer=<iss> --trust-root-ref=<root-image@digest> <image@digest>`
- UC2: `strike verify --lane=<lane.yaml> <image@digest>`
- Error if identity/issuer are provided with --lane (lane is the source)
- Exit code 0 on success; 1 on verification failure (with layer sentinel in stderr)

### 2. UC2 lane-policy integration -- LANDED

Integrate `internal/verify.Verifier` with lane policy sources:
- Load lane, extract identity, issuer, keyless endpoints from it
- Construct `TrustedMaterial` from the lane-declared trust root (via 1a)
- Resolve artifact digest from the reference (local pull if needed for referrers)
- Call `Verifier.Verify()` on each referrer bundle, accumulate results

### 3. Predicate validation and trust mode -- LANDED

Per-layer validation and trust-mode gating (`cmd/strike/verify.go`):
- Each fetched bundle is classified by its layer ("sealed", "engine-context",
  "informational") and its verified statement's predicateType checked against
  that layer.
- The sealed predicate must carry a laneDigest; under a lane policy (UC2) it
  must equal that lane's digest -- the "produced by this lane" binding, a hard
  Layer-V check.
- The exit follows the V/E model: V hard (no opt-out); E hard unless
  `--no-engine-trust`, which degrades the engine-context layer to informational;
  informational never gates. A missing engine-context/informational layer is
  reported, not silently passed.
- The golden bundles carry real predicates (instruction 3a), so this validation
  is under test rather than vacuous.

Deferred: deep schema conformance (full SLSA Provenance v1, SBOM format
compliance), base-SBOM signature verification, and a `--strict`
(require-everything-green) mode.

Depended on: instruction 1 (lane schema and UC2 integration) and instruction 3a
(enriched goldens).

## Sequencing

Per the established handover pattern:

1. Confirm lane schema extensions (instruction 1a); ratify UC1 vs UC2 CLI shape (1c)
2. Implement instruction 1 (schema + subcommand)
3. Build out instruction 2 (lane-policy integration)
4. Add instruction 3 (predicate validation) after lane trust-mode config is settled

## Invariants the roadmap must respect

- Two inputs irreducibly external to the artifact: signature trust root and
  expected identity/issuer (ADR-041 D1, D2).
- UC1 (consumer): explicit parameters; digest-pinned image references only.
- UC2 (operator): lane is the policy source; no sigstore-shaped flags needed.
- Lane declares **transport anchors** (TLS `#TLSTrust`); verifier needs
  **signature roots** (CA, keys, TSA cert). They are separate and declared
  separately (ADR-041 context).
- Digest-pinning discipline applies to all external references (trust root by
  OCI descriptor hash, images by digest, not tag).
- Every verification failure returns a layer sentinel from `internal/verify`.
- Verification is versions-sharp: artifacts built from an older lane revision
  fail against today's file (lane_digest binding).

## Open items

- **Trust-root import from OCI referrers -- resolved, not adopted.** Deriving the
  trust root from the verified image's referrers was superseded: the anchor must
  be operator-chosen, never sourced from the artifact (ADR-041 Principles).
  Trust-root material is lane bytes (`trustRoot`), the lane's digest-pinned
  `trustRootRef`, or the `--trust-root-ref` CLI override (`669eca89`); fail-closed
  `ErrNoTrustRoot` is the intended terminal when none is declared, and the verify
  path reads no host-local file. No further work.
- **Per-endpoint trust-root override -- resolved by redesign.** The sketched
  per-endpoint overrides (fulcio_root / rekor_keys / tsa_root) were not adopted;
  the shipped model is a single TrustedRoot bundle, inline (`trustRoot`) or by
  reference (`trustRootRef`). No further work.

## Cross-roadmap dependencies

- **ADR-040 instruction 5a (verify core) is the foundation.** Instruction 1
  wraps it with CLI and lane policy. No new verification logic is needed.
- **ADR-040 instruction 4 (control-plane push and referrer attach) must
  precede instruction 2 (UC2 referrer lookup).** Both are complete.
- **Lane trust-mode selection (UC1 vs UC2; engine-trust vs not) must settle
  before instruction 3 (predicate validation).** ADR-041 D2 outlines the
  choice; the lane configuration for it awaits schema design (1a).

## References

- `docs/ADR-041-lane-as-verification-policy.md` -- governing ADR
- `docs/ADR-040-control-plane-sbom-and-keyless-attestation.md` -- verify core and producer
- `docs/ADR-037-two-engine-trust-layers.md` -- the V / E trust-layer basis
- `internal/verify/verify.go` -- the verify core entry point and type definitions
- `ROADMAP-ADR-040.md` -- predecessor roadmap; instruction 5a is complete
