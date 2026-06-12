# ADR-041 Implementation Roadmap

## Status: IN PROGRESS (foundation done; instructions 1--3 remain)

ADR-041 is Accepted: the decision record is at
`docs/ADR-041-lane-as-verification-policy.md`, registered in
`docs/ADR-INDEX.md` by number.

The foundation is in place: ADR-040 instruction 5's core verify layers are
complete in `internal/verify`, tested end-to-end with golden fixtures and
live tests against the sigstore-local harness. Lane-digest computation and
enforcement have been implemented in the producer path (commit 4cfdbfe). What
remains is wrapping the verify core in the CLI, binding it to lane policy
(identity, issuer, trust root), and exposing the two verification use cases:
UC1 (consumer, explicit parameters) and UC2 (operator, lane as policy).

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

### D1 -- CLI subcommand exposure

The `strike verify` subcommand does not yet exist. When added, it will
expose the two use cases:
- UC1: `strike verify --identity=<id> --issuer=<iss> --trust-root=<path> <digest>`
- UC2: `strike verify --lane=<lane.yaml> <digest>` (identity, issuer, root from lane)

### D2 -- Lane truth source for policy

The lane's declared identity, issuer, and keyless endpoints are not yet
consumed by the verify path. When integrated, UC2 verification will source
these directly from the lane file without re-typing.

### D3 -- Trust root sourcing and override

The trust-root is currently embedded in UC1 tests as a fixture. The lane
will declare signature roots (digest-pinned by reference) and UC2 will
consume them; UC1 will accept an explicit override (--trust-root flag). The
TLS transport anchors (`#TLSTrust` on keyless endpoints) are producer
concerns; the signature roots (Fulcio CA, Rekor keys, TSA cert) are
consumer concerns, and they must be declared separately.

### D4 -- Predicate validation and trust-mode gating

ADR-040 D3 defines three predicate layers: sealed (V), engine-dependent (E),
and informational. UC2 with engine trust gates on both V and E; UC2 without
engine trust gates on V only. Per-layer validation (SLSA Provenance v1 schema,
SBOM format compliance, engine-context predicate shape) is deferred to after
instruction 3 (needs the lane configuration for trust-mode selection).

## Instruction-file sequence

CUE-first for lane schema extensions; then implementation. Each item is its
own instruction file under the established conventions.

### 1. Lane schema and verify subcommand -- PENDING

**1a.** Add `#TrustRoot` schema to `specs/lane.cue`:
- `#TrustRootRef`: digest-pinned reference (fetch by OCI descriptor, verify digest)
- `#InlineRoot`: inline PEM certificate bundle (for testing and emergency override)
- Per-keyless-endpoint optional override (fulcio_root, rekor_keys, tsa_root)

**1b.** Add to keyless config:
- Optional `trust_root` field (UC2 default; UC1 explicit override)
- Empty means "import from OCI referrers" (deferred to after instruction 3)

**1c.** Expose `strike verify` subcommand in `cmd/strike`:
- UC1: `strike verify --identity=<id> --issuer=<iss> --trust-root=<path> <image@digest>`
- UC2: `strike verify --lane=<lane.yaml> <image@digest>`
- Error if identity/issuer are provided with --lane (lane is the source)
- Exit code 0 on success; 1 on verification failure (with layer sentinel in stderr)

### 2. UC2 lane-policy integration -- PENDING

Integrate `internal/verify.Verifier` with lane policy sources:
- Load lane, extract identity, issuer, keyless endpoints from it
- Construct `TrustedMaterial` from the lane-declared trust root (via 1a)
- Resolve artifact digest from the reference (local pull if needed for referrers)
- Call `Verifier.Verify()` on each referrer bundle, accumulate results

### 3. Predicate validation and trust mode -- PENDING

Add per-layer validation and trust-mode gating:
- Parse verified payload as in-toto statement (payload type / signature path)
- Validate sealed predicate (SLSA Provenance v1 schema)
- If engine-trust: validate engine_dependent predicate (engine-context shape)
- If --sbom flag: validate SBOM predicates (format, component count)
- Exit code and message per the passing/failing layers and trust mode

Depends on: instruction 1 (lane schema and UC2 integration).

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

- **Trust-root import from OCI referrers.** ADR-041 D3 mentions "empty means
  import from OCI referrers" as a future path, but requires the referrer
  attachment to land first (ADR-040 instruction 4, done) and verification
  integration (instruction 2, pending). Exact mechanics (cert pinning in
  referrer attachment, inline vs by-reference) deferred to after instruction
  2 when the data flow is clear.
- **Per-endpoint trust-root override.** Instruction 1a sketches per-endpoint
  optional overrides (fulcio_root, rekor_keys, tsa_root). Decision: inline
  in the lane (trusted by admission), or fetch by digest? Deferred to schema
  confirmation gate (1a).

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
