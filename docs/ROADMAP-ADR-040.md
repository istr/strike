# ADR-040 Implementation Roadmap

## Status: SUBSTANTIALLY COMPLETE (instructions 1--4 done; instruction 5 core done, CLI exposure pending)

ADR-040 is Accepted and fully plumbed: the decision record is at
`docs/ADR-040-control-plane-sbom-and-keyless-attestation.md`, registered in
`docs/ADR-INDEX.md` by number and by principle, with the partial-supersession
back-reference to ADR-019 and the extension note to ADR-037 in place.

D1 through D4 are complete (instructions 1--4: OIDC schema, SBOM cataloging,
keyless statement projection and signing, OCI referrer attachment, and
control-plane push). Instruction 5 (strike verify) has its core verify layers
fully implemented and tested (trust root parsing, bundle shape validation,
DSSE signature verification, Fulcio certificate chain and identity binding,
RFC3161 timestamp verification, and Rekor v2 transparency-log inclusion);
golden-test fixtures verify the full end-to-end chain. The `strike verify`
subcommand exposure to the CLI and its lane-policy integration remain pending.
This work has been superseded by ADR-041 scope; see "Cross-roadmap
dependencies".

## What has landed

- **ADR-040 plumbing.** Decision record placed, indexed, cross-referenced.
  Status flipped to Accepted.
- **Instruction 1a -- lane-wide OIDC identity (D5).** `#OIDCConfig` added to
  `specs/lane.cue` with generated Go type. The lane carries the declared
  signing identity (issuer + identity) that ADR-040 D5 cross-checks against
  the Fulcio certificate.
- **Instruction 1b -- output predicate types (D3).** `specs/predicate.cue`
  defines the two standard-ecosystem attestation shapes: a sealed (Layer V)
  in-toto Statement v1 wrapping SLSA Provenance v1
  (`#SLSAProvenanceStatement`), and an engine_dependent (Layer E) statement
  wrapping a strike-defined engine-context predicate
  (`#EngineContextStatement`). Hand-written Go types in
  `internal/deploy/predicate.go`, validated against the embedded CUE schema.
  The internal `#Attestation` collect-model is unchanged; projection into
  these output shapes is instruction 3.
- **Instruction 2a -- base-SBOM signer schema + native SBOM cataloger (D1).**
  `#SBOMSigner` added to `specs/lane.cue` (optional lane-wide
  `base_sbom_signers` list). Native SBOM cataloger in
  `internal/executor/catalog.go`: strike-owned npm lockfile, dpkg status,
  and go-buildinfo parsers, CycloneDX via `cyclonedx-go`, SPDX 2.3 via
  `spdx/tools-golang` (model + JSON only). osv-scalibr ruled out by two
  import-surface measurements (D1 mechanism amendment appended to ADR-040).
- **Instruction 2b -- wire cataloger into Pack, remove buildinfo path (D1).**
  `Pack` now flattens the assembled image into an in-memory `fs.FS`
  (`internal/executor/flatten.go`) and catalogs it in-process via
  `GenerateImageSBOM`, emitting both CycloneDX and SPDX 2.3 bound to the
  artifact's digest as separate OCI referrers. The buildinfo `GenerateSBOM`
  path (`internal/executor/sbom.go`) is removed in its entirety, together
  with the unverified ADR-019 base-SBOM referrer fetch and the
  `AssembleResult.BinaryPath` plumbing. An empty catalog is surfaced as
  INFO. Engine-backed e2e test verifies the full pipeline. Verified
  base-SBOM ingestion against `base_sbom_signers` is deferred to after
  instruction 5 (needs the Fulcio/Rekor verification machinery).
- **Decision basis: two spikes (both complete).**
  - scalibr import-surface spike (PARTIAL result): the heavy clusters
    (container-runtime, grpc, sqlite, vuln, TUI, cloud crypto, resolution)
    prune under `fs.FS` plus avoiding the `extractor/filesystem/list`
    aggregator. The disk-image cluster (go-diskfs / ext4 / ntfs) remains via
    the unconditional `extractor/filesystem -> embeddedfs/common` import; the
    D1 thin walker handles it, and a parallel upstream PR decouples it.
  - keyless import-surface spike (COMPOSED-COVERS result): the composed set
    (sigstore-go/pkg/sign + sigstore/pkg/oauthflow + go-containerregistry)
    compiles the full chain (OIDC -> Fulcio -> DSSE -> Rekor v2 -> referrer
    attach) at roughly one third the binary size of cosign-as-a-library and
    without the cloud-KMS provider clusters. Decision: compose. Subsequent
    D-3b-1 decision: demote sigstore-go to test-only crossval oracle; produce
    bundles hand-rolled via protobuf-specs (smaller dependency surface).
- **Instruction 3b-i -- hand-rolled keyless bundle core (D2).**
  `internal/deploy/keyless.go`: `signStatementKeyless` signs a projected
  in-toto statement with an ephemeral key in ASN.1 DER ECDSA (sigstore
  verifiers reject strike's internal raw r||s format);
  `assembleKeylessBundle` builds a sigstore v0.3 bundle (single leaf cert,
  Rekor v2 tlog entry, RFC3161 timestamp -- no SET, trusted time from the
  timestamp) and marshals it via protojson. `protobuf-specs` is the only
  new production dependency. `internal/deploy/keyless_test.go`: a hermetic
  crossval test signs a fixture with strike's DER signing and verifies the
  assembled bundle against sigstore-go's `pkg/verify` (`VirtualSigstore`
  trust root, `WithTransparencyLog` + `WithSignedTimestamps`). sigstore-go
  is a test-only oracle and stays out of the binary's import graph. This
  closes the D-3b-1 open question: a DSSE signature strike produces verifies
  under the canonical sigstore verifier.
- **Decision basis: D-3b-1 (ratified).** The hand-rolled producer
  (sigstore-go demoted to test-only crossval oracle) is ratified. strike
  signs in ASN.1 DER and assembles the bundle itself using protobuf-specs;
  sigstore-go is the verification oracle, never a production dependency.
- **Instruction 3b-ii-a -- TLS-only keyless harness (parallel track).**
  `test/sigstore-local/`: Keycloak + Fulcio + Rekor v2 (POSIX) + TSA
  behind a Caddy TLS terminator under one internal root; sslip.io
  canonical hostnames; token, rekor-pubkey, and tsa-certchain Makefile
  targets. See `docs/ROADMAP-sigstore-test-harness.md` for the as-built
  record.
- **Instruction 3b-ii-b -- keyless endpoints schema, clients, producer
  (D2).** `#KeylessEndpoints` in `specs/lane.cue` (Fulcio, Rekor v2, TSA,
  each with a pinned `#TLSTrust`); direct HTTP clients
  (`internal/deploy/keyless_clients.go`: Fulcio cert issuance, plain
  Rekor v2 POST -- rekor-tiles generated proto types only, no
  `pkg/client` -- RFC3161 TSA via `digitorus/timestamp`); the per-deploy
  producer (`keyless_producer.go`: one ephemeral key, one certificate,
  per statement DSSE -> timestamp -> inclusion -> v0.3 bundle). Env-gated
  live test (`TestKeylessLive`) runs the real chain against the harness.
  The ambient token is `SIGSTORE_ID_TOKEN` (D-3b-4); no oauthflow import.
- **Instruction 3b-ii-c -- keyless cutover (D2).** `signStatements`
  produces three sigstore v0.3 bundles via `produceKeylessBundles`,
  fail-closed (D-3b-2): no unsigned fallback, no fail-open Rekor path.
  `keyless:` is a required lane field (requiredness follows consumption,
  F1=2); all lane fixtures carry a canonical placeholder block. The
  Deployer lost `SigningKey`/`KeyPassword`/`Rekor` (F3: keyless means no
  key); `SignedStatement` carries a bundle, and `SignedStatement.Rekor`
  plus the `Sealed.Rekor` mirror (and its schema field) fell -- the
  bundle subsumes the transparency proof (D-3b-6). `cmd/strike` writes
  `*.sigstore.json` instead of `*.dsse.json`. ADR-040 D2 carries a
  blockquote amendment recording the as-built import surface. The
  operator-key statement path (`SignStatement`, `signOne`,
  `submitStatementsToRekor`) is removed; a nil-defaulted unexported
  producer seam keeps the Execute unit tests hermetic (F2). Artifacts
  stay on the v1 operator-key path until instruction 5 (D-3b-5), so
  `SignAttestation`, `signDSSE`, and `internal/verify` are untouched
  (D-3b-3). End-to-end deploy integration coverage is deliberately
  deferred to the strike-verify arc (instruction 5).
- **Verify foundation (from ADR-037).** The `internal/verify` package
  (DSSE envelope parsing, payload-type guard, ECDSA P-256 signature
  verification over PAE) exists and is the base instruction 5 builds on. It
  was written for the operator-held-key path and is reoriented, not
  discarded, under keyless (see instruction 5).

## What is NOT yet implemented

Grounded against the current snapshot.

### D1 -- control-plane SBOM over the sealed artifact -- DONE (2a + 2b)

**Done (instruction 2a).** The `#SBOMSigner` schema (trusted base-SBOM
signer identity) is in `specs/lane.cue` with generated Go type. The native
SBOM cataloger (`internal/executor/catalog.go`) catalogs an extracted root
filesystem (`fs.FS`) into canonical CycloneDX and first-class SPDX 2.3,
using strike-owned npm lockfile, dpkg status, and go-buildinfo parsers
rendered through `cyclonedx-go` and `spdx/tools-golang` (model + JSON
sub-packages only). osv-scalibr is not used (D1 mechanism amendment).
Output is canonicalized (deterministic serial/namespace, SOURCE_DATE_EPOCH
timestamp, stable ordering).

**Done (instruction 2b).** `Pack` flattens the assembled image into an
in-memory `fs.FS` (`internal/executor/flatten.go`) and catalogs it via
`GenerateImageSBOM`, emitting both CycloneDX and SPDX 2.3 as separate OCI
referrers bound to the artifact's digest. The buildinfo `GenerateSBOM`
path and the unverified ADR-019 base-SBOM referrer fetch are removed in
their entirety. An empty catalog is surfaced as INFO. Engine-backed e2e
test verifies the full pipeline including determinism.

**Deferred.** Verified base-SBOM ingestion against the declared
`base_sbom_signers` is deferred to after instruction 5 (needs the
Fulcio/Rekor verification machinery). Base OS packages are still captured
for catalogable bases because flattening includes the base layers and the
cataloger reads their dpkg database directly.

### D2 -- keyless signing, in-process -- DONE (3b-i + 3b-ii)

The full chain is live in the deploy path: one ephemeral key and one
Fulcio certificate per deploy, then per statement DSSE -> RFC3161
timestamp -> Rekor v2 inclusion -> sigstore v0.3 bundle, fail-closed
(D-3b-2). `keyless:` is a required lane field; the Deployer carries no
key material and no Rekor client. The only durable secret in the
statement path is the OIDC identity (ambient `SIGSTORE_ID_TOKEN`,
D-3b-4). Remaining D2 surface: the v1 operator-key artifact path
(`executor.Pack`) cuts over in instruction 5 (D-3b-5).

### D3 -- cosign-compatible OCI referrers, layered by trust -- DONE

The three layers (sealed V / engine_dependent E / informational) are now
physically separate, co-attached OCI referrers on the pushed digest (sealed =
standard SLSA Provenance v1; engine_dependent = the strike-defined predicate
type `https://istr.dev/strike/predicates/engine-context/v1`; informational =
signed byproducts that never gate). The output predicate types are defined
(instruction 1b), the projection from the internal `#Attestation` into the
three statements is live (instruction 3a), each statement is signed keylessly
as its own sigstore bundle (instruction 3b), the bundles are attached as
referrers on the registry digest (instruction 4), and the per-layer
verification exit is implemented (instruction 5a, exposed via ADR-041). The
V / E boundary is physical, not a convention inside one signature.

### D4 -- the control plane owns the registry push -- DONE

The control plane pushes the assembled image via go-containerregistry
`remote.Write`; signing and referrer attachment run on the registry digest, so
the signature covers the artifact as it exists on the wire. The engine pulls by
digest but never pushes.

### D5 -- lane-wide OIDC identity, pinned -- DONE (instruction 1a)

`#OIDCConfig` added to `specs/lane.cue` with generated Go type (instruction
1a). The declared identity (issuer + identity) is carried into the sealed
provenance's `externalParameters.oidc` (instruction 1b). The Fulcio
certificate cross-check (cert issuer == declared issuer, cert SAN ==
declared identity) is instruction 5.

## Instruction-file sequence

CUE-first, then implementation. Each item is its own numbered instruction
file under the established conventions (Goal, Why, Confirmation Gate,
Sequence, What NOT to do, Anti-initiative clause, Acceptance criteria,
copy-paste-ready Commit message). Each verifies in its acceptance criteria
that `docs/ADR-INDEX.md` reflects ADR-040. None of these files is written
until its design fork is ratified; instruction 1 (schema) is written and
landed before any implementation instruction.

### 1. CUE schema (D5 + the D3 predicate shapes) -- DONE

**1a (D5).** Added `#OIDCConfig` to `specs/lane.cue` with generated Go type.

**1b (D3).** Defined the two output predicate types in `specs/predicate.cue`
with hand-written Go types in `internal/deploy/predicate.go`: sealed SLSA
Provenance v1 statement (`#SLSAProvenanceStatement`) with strike's typed
`externalParameters` (including the declared OIDC identity, peers, observed
peers, resolver, engine connection), and the engine-context statement
(`#EngineContextStatement`) carrying only Layer-E claims (peer attribution,
engine metadata). Validated against the embedded CUE schema in
`predicate_test.go`. The internal `#Attestation` collect-model is unchanged.

### 2. SBOM core (D1) -- DONE (2a + 2b)

**2a (done).** Added the `#SBOMSigner` schema and optional lane-wide
`base_sbom_signers` field. Built a native SBOM cataloger
(`internal/executor/catalog.go`) that catalogs an extracted root filesystem
(`fs.FS`) into canonical CycloneDX and first-class SPDX 2.3. Two
import-surface measurements ruled out osv-scalibr (D1 mechanism amendment
appended to ADR-040): its extractors pull the go-diskfs/ext4/ntfs disk-image
cluster at import time, and its converter-only path drags go-git plus
go-funk/osv-schema/stringset. Instead, strike parses `package-lock.json`,
dpkg `status`, and Go binaries (`debug/buildinfo`) with native parsers and
renders through `cyclonedx-go` (v0.11.0, stays direct) and
`spdx/tools-golang` (v0.5.7, model + JSON only).
`package-url/packageurl-go` (v0.1.6) added for PURL construction. Output is
canonicalized (deterministic serial/namespace from subject digest,
SOURCE_DATE_EPOCH timestamp, stable component ordering).

**2b (done).** `Pack` flattens the assembled image into an in-memory `fs.FS`
(`internal/executor/flatten.go` -- single backing `[]byte`, no disk I/O, no
unpack/read race) and catalogs it in-process via `GenerateImageSBOM`,
emitting both CycloneDX and SPDX 2.3 as separate OCI referrers bound to the
artifact's digest. The buildinfo `GenerateSBOM` path
(`internal/executor/sbom.go`) is removed in its entirety (deletion, not a
fix), together with the unverified ADR-019 base-SBOM referrer fetch
(`ProbeBaseImageSBOM` and helpers, the `SBOMSource` type,
`sbomArtifactTypes`) and the dead `AssembleResult.BinaryPath` plumbing. An
empty catalog is surfaced as INFO. Engine-backed e2e test
(`test/integration/sbom_test.go`) verifies two SBOM referrers, correct
subject, npm/dpkg/golang components, and deterministic output.

Verified base-SBOM ingestion against `base_sbom_signers` is deferred to
after instruction 5 (needs Fulcio/Rekor verification machinery). Base OS
packages are still captured for catalogable bases because flattening includes
the base layers and the cataloger reads their dpkg database directly.

### 3. Statement projection and keyless signing (D2 + D3)

**3a (done).** Project the internal `#Attestation` into the three output
in-toto statements and sign each as its own operator-key DSSE: sealed SLSA
Provenance v1 (Layer V), engine-context (Layer E, with `EngineMetadata`
reclassified per Fork C and the engine-asserted peer attribution), and a new
informational statement (`specs/predicate.cue`,
`internal/deploy/predicate.go`). `Attestation.SignedEnvelope` becomes
`Attestation.Signed` (three envelopes plus per-statement Rekor entries); each
is submitted to Rekor and written as its own DSSE file. The projected
statements carry `application/vnd.in-toto+json` (ADR-040 D3 supersedes
ADR-013's payload type for the output). The OCI-referrer attach is deferred
to instruction 4: the deploy attestation is recorded in lane state plus Rekor
plus the output dir today, and the three referrers materialize on the pushed
digest.

**3b-i (done).** Hand-rolled keyless bundle core: `signStatementKeyless`
(ASN.1 DER ECDSA signing) and `assembleKeylessBundle` (sigstore v0.3 bundle
assembly via protobuf-specs). Hermetic crossval test signs a fixture with
strike's DER signing and verifies the assembled bundle against sigstore-go's
`pkg/verify`. sigstore-go is a test-only oracle (not in the binary's import
graph). `protobuf-specs` is the only new production dependency. D-3b-1
ratified the hand-rolled producer.

**3b-ii (done, in three steps).** The keyless core is wired into the
deploy path:

- **3b-ii-a** -- the TLS-only local harness (parallel track; see
  `docs/ROADMAP-sigstore-test-harness.md`).
- **3b-ii-b** -- `#KeylessEndpoints` schema, Fulcio/Rekor v2/TSA HTTP
  clients, the per-deploy bundle producer, and the env-gated live test
  against the harness. Token acquisition is ambient (`SIGSTORE_ID_TOKEN`,
  D-3b-4) -- no oauthflow, never interactive.
- **3b-ii-c** -- the cutover: `signStatements` goes keyless fail-closed,
  `keyless:` becomes required, the operator-key statement path and the
  Deployer's key/Rekor fields are removed, three `*.sigstore.json`
  bundles replace the three `*.dsse.json` envelopes, and
  `SignedStatement.Rekor`/`Sealed.Rekor` fall (D-3b-6).

The reorientation of `internal/verify`, originally listed under 3b-ii,
was ratified out of the cutover (D-3b-3) and is instruction 5 work, where
the verification model changes anyway. This completed the cross-roadmap
unblock: see "Cross-roadmap dependencies".

### 4. Control-plane push (D4)

The control plane pushes the assembled image via go-containerregistry
`remote.Write`. Remove any engine push path; the engine may still pull by
digest for now but never pushes. Signing and referrer attach (instruction 3)
move to run after the control-plane push, on the registry digest, so the
signature covers the artifact as it exists on the wire.

Depends on: instruction 3 (sign-and-attach runs on the pushed digest).

### 5. strike verify (D3 verification exit + D5 cross-check) -- CORE DONE, CLI EXPOSURE PENDING

**5a (done).** Core verify layers fully implemented in `internal/verify`:
- `ParseBundle` and `ParsedBundle`: strict sigstore v0.3 bundle shape validation
- `TrustedTime`: RFC3161 timestamp extraction and validation
- `Leaf`: Fulcio certificate chain verification and identity binding (issuer == declared issuer, SAN == declared identity)
- `DSSE`: in-toto statement envelope verification (payload type guard, ECDSA P-256 signature over PAE)
- `Inclusion`: Rekor v2 transparency-log inclusion proof verification
- `Verify`: end-to-end entry point combining all layers in fail-closed order
- `ParseTrustedRoot`: Fulcio root/intermediates, TSA root/intermediates/leaf, and Rekor v2 key parsing from sigstore TrustedRoot bundles

Golden-test fixtures (`internal/deploy/verify_golden_gen_internal_test.go`,
`internal/verify/layers_test.go`, `internal/verify/differential_test.go`)
verify the full chain offline with known-good bundles. Live test
(`internal/deploy/keyless_live_internal_test.go`) exercises the producer
end to end against the sigstore-local harness.

**5b (deferred to ADR-041).** CLI exposure, lane-policy binding, and predicate
validation per-layer trust mode are now ADR-041 work (see "Cross-roadmap
dependencies"). The core verification engine is ready to be wrapped; ADR-041
instruction 1 will integrate it into `cmd/strike verify`.

Instruction 5 also absorbed the work items the 3b arc deferred to it: the v1
operator-key artifact path cuts over to keyless (D-3b-5 done; `executor.Pack`'s
`SigningKey`/`Rekor` options, `signDSSE`, `SignAttestation`, and `#RekorEntry`
retired), `internal/verify` is reoriented from operator-key DSSE to bundle
verification (D-3b-3 done), verified base-SBOM ingestion against
`base_sbom_signers` is possible (deferred to verification time), and
end-to-end deploy integration coverage returns as golden and live tests over
real bundles (5a done).

Depends on: instructions 1, 3, 4 (predicate shapes, keyless signatures, the
pushed registry digest the referrers hang off). Subsumes and redefines the
verify item the ADR-037 roadmap carried (see "Cross-roadmap dependencies").

## Parallel tracks (outside the strike code sequence)

- **osv-scalibr decoupling PR (upstream).** No longer needed for strike:
  the D1 mechanism amendment (instruction 2a) ruled out osv-scalibr entirely
  in favor of native parsers. The upstream decoupling is organic ecosystem
  work only.
- **Local sigstore test harness -- LANDED (H1).** `test/sigstore-local/`:
  Keycloak + Fulcio + Rekor v2 (POSIX) + TSA behind a Caddy TLS
  terminator, all endpoints HTTPS under one exported internal root,
  sslip.io canonical hostnames, digest-pinned images. It exercises the
  live chain (`TestKeylessLive`) and supports instruction 5; it is not
  part of the trusted binary. WebAuthn/FIDO2 hardening (H2) remains. See
  `docs/ROADMAP-sigstore-test-harness.md`.

## Cross-roadmap dependencies and ordering

- **ADR-040 instruction 3 (keyless) satisfies the ADR-038 D5.1 ordering
  dependency for the statement path.** ADR-038's roadmap records that the
  signing key must be externalized (KMS / keyless) before the front's
  inbound listener is exposed in a remote deployment. Instruction 3 is
  done: deploy statements sign keylessly and the Deployer holds no key
  material; their only durable secret is the OIDC identity. The
  externalization is complete once the v1 operator-key artifact path also
  cuts over (instruction 5, D-3b-5) -- until then `executor.Pack` still
  loads the operator key, so remote-front exposure waits for
  instruction 5. **DONE**: The operator-key artifact path has been retired
  (commit 4cfdbfe); keyless is now the exclusive path.

- **ADR-040 instruction 5 (verify core) is complete; CLI exposure moves to
  ADR-041.** The ADR-037 roadmap listed the `strike verify` CLI subcommand
  as a pending item. ADR-040's scope encompasses the verification engine
  (core layers, golden tests, live tests). ADR-041 redefines the CLI's
  higher-level scope (lane-policy binding, trust-mode-driven predicate
  validation, identity and issuer sourcing) and inherits the ready
  `internal/verify` core. Instruction 5a (core) is done; 5b (CLI exposure)
  is now part of ADR-041 instruction 1. `internal/verify` is the completed
  foundation that ADR-041 wraps.

## Invariants the roadmap must respect

- Trust layers V (verify / observe; no false positive) and E
  (engine-dependent; silent false negative) per ADR-037, plus a non-gating
  informational bucket. ADR-040 D3 makes the V / E boundary physical (separate
  referrers), not a convention inside one signature.
- SLSA L3 under engine trust; L2+ otherwise, losing only complete
  externalParameters and build isolation. That single distinction surfaces as
  whether the E predicate is trusted (instruction 5).
- The control plane owns the wire: it pushes (D4) and already dials peers
  (container -> engine -> front -> capsule -> peer). The engine pulls but
  never pushes.
- Identity-first: signing identity (OIDC / Fulcio), peer identities (trust
  anchors, now including the IdP as a declared peer with a pinned anchor),
  artifact identity (digest). No long-lived key to hold.
- Everything external is digest-pinned; reproducibility is enforced
  (canonicalized SBOM, SOURCE_DATE_EPOCH, stable ordering); the signature
  covers the registry digest the control plane pushed.
- Code is liability: the cataloger and the signing stack are the leanest
  audited libraries that cover the task (measured by the two spikes); native
  parsers plus format libraries are chosen over a heavy dependency. No exec:
  the keyless flow runs in-process as libraries, never by spawning a CLI.

## Open items

- **ADR granularity (carry-over from the handover).** ADR-040 was written and
  plumbed as one consolidating ADR; the index now lists it as a single
  Accepted record. The handover left open whether to decompose it into
  separate ADRs (SBOM generation / keyless signing / predicate packaging / CP
  push / OIDC schema), allocating ADR-041 ff. Permanent ADR numbering makes
  the split cheap but it must be decided before instruction 1 if a split is
  wanted. Default, absent a decision: keep ADR-040 consolidated as plumbed.
- **ADR-038 index discrepancy (flag, do not fix here).** The ADR-038 decision
  record states Status: Accepted, but `docs/ADR-INDEX.md` lists ADR-038 as
  Proposed. This is a pre-existing inconsistency, surfaced for the operator;
  it is not ADR-040 work. (The earlier ADR-039 index gap noted in the
  handover is now resolved -- 039 is present and Accepted.)

## References

- `docs/ADR-040-control-plane-sbom-and-keyless-attestation.md` -- governing ADR
- `HANDOVER-ADR-040-roadmap.md` -- design handover and decision basis
- `SPIKE-scalibr-import-surface.md`, `SPIKE-keyless-import-surface.md` -- the
  measurement spikes behind D1 and D2
- `sigstore-keyless-fido2-report.md` -- keyless / FIDO2 evaluation and the
  local-stack recommendation
- `docs/ADR-037-two-engine-trust-layers.md` -- the V / E trust-layer basis
- `docs/ADR-019-sbom-as-oci-referrer.md` -- SBOM mechanism partially superseded
  (referrer attachment and base-image resolution order retained)
- `docs/ADR-013-...` -- DSSE envelope and Rekor; `sealed.rekor` stripping retained
- `docs/ADR-038-protocol-mediated-ssh.md` -- the D5.1 ordering dependency
