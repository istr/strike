# End-to-end attestation: typed provenance, outcome signing, and integration tests

## The convergence

Two problems have the same solution:

1. **Attestation gap**: strike's deploy attestation captures {pre_state,
   action, post_state} but lacks two bookends -- source provenance
   (who committed the code?) and outcome signing (is the attestation
   itself tamper-proof?).

2. **Coverage gap**: 59.2% overall. The untested code (executor/pack,
   executor/sbom, registry/client -- all ~35-50%) requires a real
   container engine and registry. Unit tests cannot reach it.

Integration tests that run a full lane (source -> build -> pack ->
sign -> deploy -> attest) close both gaps at once: they exercise the
untested code paths AND validate the end-to-end attestation chain.

---

## Part 1: Provenance in attestations

### What to capture

Each step in a lane can declare a `provenance` spec that names a
type (`git`, `tarball`, `oci`, `url`) and a container path where
the step writes a JSON provenance record. The record is validated
against the type-specific CUE schema in `specs/source-provenance.cue`
at capture time (step 04).

At deploy time, the deployer traverses the DAG backwards from the
deploy step and collects all validated provenance records from
predecessor steps. The attestation carries them in a `provenance`
array, sorted deterministically by step name:

```json
{
  "deploy_id": "a1b2c3d4e5f67890",
  "provenance": [
    {
      "type": "git",
      "raw": {
        "type": "git",
        "uri": "https://github.com/foo/bar.git",
        "commit": "abc123def456...",
        "ref": "refs/heads/main",
        "signature": {
          "method": "gpg",
          "verified": true,
          "signer": "dev@example.com",
          "fingerprint": "ABCD1234"
        }
      }
    }
  ],
  "artifacts": { "..." : "..." },
  "pre_state": {},
  "post_state": {}
}
```

### Design decisions

**Provenance is step-declared, not auto-detected.** Each step
explicitly declares what type of provenance it produces and where
the record file lives. This is more general than the old git-only
source provenance and supports tarball, OCI, and URL sources.

**Validation happens at capture time.** The raw JSON record is
validated against the CUE schema for its declared type before being
stored in lane state. Invalid records fail the step.

**DAG traversal collects transitive provenance.** The deploy step
does not need to know which predecessor steps have provenance. It
walks the DAG and collects all records.

**Null when empty.** Go nil slices serialize to JSON `null`. The
CUE schema allows `[...{...}] | null`.

### CUE schema (attestation.cue)

In `#Attestation`:
```cue
provenance: [...{type: "git" | "tarball" | "oci" | "url", raw: _}] | null
```

No wrapper type — the records are already validated at capture time.
Type-specific record schemas are in `specs/source-provenance.cue`.

---

## Part 2: Deployment outcome signing

### What to sign

The `Attestation` JSON produced by `deploy.Execute()` is currently
written to a file but not cryptographically signed. Signing it
closes the chain: the same key that signs the image manifest also
signs the attestation that records its deployment.

### DSSE envelope format

Use the **Dead Simple Signing Envelope** (DSSE, in-toto v1 standard).
This is what cosign, Tekton Chains, and GitHub artifact attestations
all use:

```json
{
  "payloadType": "application/vnd.strike.attestation+json",
  "payload": "<base64url of canonical attestation JSON>",
  "signatures": [
    {
      "keyid": "sha256:<public key fingerprint>",
      "sig": "<base64 of ECDSA-P256-SHA256 signature>"
    }
  ]
}
```

### Design decisions

**Reuse existing signing infrastructure.** `executor.SignManifest`
already handles ECDSA P-256 key loading, cosign key decryption,
and signature production. Extract the core signing logic into a
shared function:

```go
// SignPayload signs arbitrary data with the loaded ECDSA key.
// Returns base64-encoded raw (r||s) signature.
func SignPayload(data, keyPEM, password []byte) (string, error)
```

`SignManifest` calls `SignPayload` internally. `SignAttestation`
(new) wraps the attestation JSON in DSSE and calls `SignPayload`.

**Store as OCI artifact.** The signed attestation is attached to
the deployed image as an OCI 1.1 referrer, just like the SBOM and
signature already are. The artifact type is
`application/vnd.strike.attestation+json`. This means any OCI
registry that supports referrers (most do in 2026) stores the full
chain: image + SBOM + signature + deploy attestation.

**Sign with the cosign key from secrets.** The deploy step already
has access to secrets (for Kubernetes auth, custom deploys). Adding
`cosign_key` and `cosign_password` to the deploy step's secrets
enables signing. If no key is available, the attestation is written
unsigned (with a warning). This matches the existing pattern in
pack steps.

### Implementation path

1. **Extract `SignPayload` from `executor/sign.go`.** This is a
   refactor of the existing signing code, not new crypto. The
   function takes `(data, keyPEM, password []byte)` and returns
   `(b64sig string, keyID string, err error)`. `keyID` is the
   SHA-256 fingerprint of the public key.

2. **Add `SignAttestation` function to `internal/deploy/`.** Takes
   attestation JSON + key PEM + password, returns DSSE envelope
   JSON. Implementation:
   - Canonicalize attestation JSON (json.Marshal, not MarshalIndent)
   - Base64url-encode (no padding)
   - Call `SignPayload`
   - Build DSSE envelope
   - Return envelope JSON

3. **Extend `Deployer.Execute()`** to sign the attestation after
   validation (step 7.5 in the current flow). If signing key is
   available:
   - Call `SignAttestation`
   - Write `attestation-signed.json` (DSSE envelope) alongside
     `attestation.json` (raw, for debugging)
   - If the deploy target is a registry: push as OCI referrer

4. **Extend lane schema** (optional): add `sign` field to
   `#AttestationSpec` to configure attestation signing:
   ```cue
   sign?: {
       enabled: *true | bool
       key?:    string  // secret ref
   }
   ```

5. **Verification function:** Add `VerifyAttestationSignature`
   that takes DSSE envelope JSON + public key PEM and verifies
   the signature. This is the consumer-side function that a
   verifier (or the next strike deploy) uses to check the chain.

---

## Part 3: Integration tests

### Prerequisites

Integration tests require:
- Podman socket (detected via `$CONTAINER_HOST` or standard paths)
- Network access to pull base images (or pre-cached images)
- Auto-detected; set `STRIKE_INTEGRATION=0` to skip (per AGENTS.md)

**No external registry required.** Use `podman run -d registry:2`
to start a local OCI registry inside the test, or use Podman's
local store exclusively (load via `ImageLoad`, inspect via
`ImageInspect`). The local registry approach is more realistic.

### Test structure

Create `test/integration/` with:

```
test/integration/
    integration_test.go      # test gate, helpers
    helpers_test.go          # shared test infrastructure
    pack_pipeline_test.go    # full pack pipeline
    deploy_attestation_test.go # full deploy + attestation
    chain_test.go            # end-to-end chain verification
    testdata/
        src/                 # minimal Go program for build tests
```

All tests use `package integration_test` and import the internal
packages. Each test calls `needsEngine(t)` which auto-detects the
podman socket and skips if unavailable:

```go
func needsEngine(t *testing.T) container.Engine {
    t.Helper()
    if os.Getenv("STRIKE_INTEGRATION") == "0" {
        t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
    }
    engine, err := container.New()
    if err != nil {
        t.Skipf("no container engine: %v", err)
    }
    if err := engine.Ping(context.Background()); err != nil {
        t.Skipf("container engine not responding: %v", err)
    }
    return engine
}
```

### Test cases

**TestPackPipeline** -- exercises executor/pack, executor/sbom,
executor/sign, registry/client:

1. Write a minimal Go program to `t.TempDir()/src/main.go`
2. Start a local registry container (`registry:2`)
3. Create a lane programmatically:
   - Step 1: build (go image, `go build -o /out/app`)
   - Step 2: pack (base: static image, file: build.app -> /app)
4. Execute the lane using the internal API:
   - `lane.Parse` -> `lane.Build` -> step iteration
   - Use real `container.Engine` from `container.New()`
5. Verify:
   - Pack produced an OCI tar
   - Image loaded into local store
   - SBOM attached as referrer
   - Signature attached as referrer
   - Manifest digest matches spec hash expectation

Coverage impact: executor/pack.go (29.8% -> ~80%),
executor/sbom.go (3.5% -> ~60%), executor/sign.go (43.8% -> ~80%),
registry/client.go (20% -> ~70%).

**TestDeployAttestation** -- exercises deploy/deploy.go:

1. Prepare a packed image (from TestPackPipeline or helper)
2. Create a deploy lane with registry method (local registry)
3. Execute deploy with state capture
4. Verify:
   - Attestation has pre_state and post_state
   - Attestation validates against CUE schema
   - If signing key provided: DSSE envelope is valid, signature
     verifies with public key

**TestEndToEndChain** -- the full chain:

1. Build test binary in a container
2. Pack into signed OCI image
3. Deploy with attestation
4. Verify the complete chain:
   - `artifacts` maps to the packed image digest
   - Attestation validates against CUE schema
   - Attestation signature verifies with the cosign public key
   - Round-trip through DSSE envelope preserves all fields
   - Engine identity present

### Chain properties verified by TestEndToEndChain

| Property | How verified |
|----------|-------------|
| Provenance chain | `att.Provenance` collects predecessor step records |
| Build determinism | Two pack runs produce identical digest (TestPackPipeline) |
| Artifact binding | `att.Artifacts["app"]` == packed image digest |
| Attestation schema | `ValidateAttestation(att)` passes CUE validation |
| Attestation signing | DSSE envelope verifies with cosign public key |
| Attestation integrity | Round-trip: sign -> verify -> unmarshal matches original |
| Engine traceability | `att.Engine` records connection type and cert fingerprints |

### What is NOT yet verified (future work)

| Property | What is needed |
|----------|---------------|
| Provenance with signatures | Steps that produce signed provenance records |
| Pre/post state capture | State capture containers in test lane |
| Drift detection | Two successive deploys with state change |
| Rekor transparency | Rekor submission in sign.go |
| Registry-based deploy | Local registry container in test |

### Local registry helper

```go
func startLocalRegistry(t *testing.T, engine container.Engine) string {
    t.Helper()
    ctx := context.Background()

    // Pull registry image
    ref := "docker.io/library/registry@sha256:..."  // digest-pinned
    engine.ImagePull(ctx, ref)

    // Run registry on random port
    exitCode, err := engine.ContainerRun(ctx, container.RunOpts{
        Image:   ref,
        Network: "",  // bridge
        Remove:  false, // cleanup in t.Cleanup
        // ... port mapping via env
    })
    // ... extract assigned port, return "localhost:<port>"

    t.Cleanup(func() {
        // stop and remove registry container
    })
    return registryAddr
}
```

---

## Part 4: Coverage projections

### Current state (post unit-test work)

| Package | Coverage | Blocker |
|---------|----------|---------|
| lane | 91.0% | -- |
| container | 78.7% | -- |
| deploy | 70.7% | state capture needs engine |
| registry | 50.5% | client needs engine + registry |
| executor | 36.5% | pack/sbom/sign need engine + files |
| cmd/strike | 35.8% | cmdRun needs engine |

### After integration tests

| Package | Projected | Notes |
|---------|-----------|-------|
| lane | 91% | no change needed |
| container | 82% | more API paths exercised |
| deploy | 85% | state capture, attestation signing |
| registry | 75% | client load, push, inspect |
| executor | 75% | pack pipeline, sbom generation |
| cmd/strike | 50% | cmdRun partial (no full CLI test) |
| **overall** | **~78%** | within 75-80% target |

---

## Execution order

### Phase 1: Attestation signing (no new schema, no git)

1. Extract `SignPayload` from `executor/sign.go`
2. Add `SignAttestation` + `VerifyAttestationSignature` to deploy
3. Wire into `Deployer.Execute()` (optional, key-dependent)
4. Unit tests for signing/verification (reuse test key infra)
5. Crossval vector: `test/crossval/sign/attestation_dsse.json`

This is self-contained, no new dependencies, no schema changes.

### Phase 2: Integration test infrastructure

1. Create `test/integration/` structure
2. Implement `startLocalRegistry` and engine helpers
3. Write `TestPackPipeline` (largest coverage impact)
4. Write `TestDeployAttestation` (exercises signed attestation)

### Phase 3: Typed provenance (refactor-b)

1. Define `#ProvenanceRecord` types in `specs/source-provenance.cue`
2. Add `#ProvenanceSpec` to lane schema, `#AttestationProvenance` to attestation schema
3. Implement `ValidateProvenance` (CUE-based validation at capture time)
4. DAG traversal via `CollectProvenance` wires records into attestation
5. Write provenance validation unit tests

### Phase 4: End-to-end chain test

1. Write `TestEndToEndChain` exercising build -> pack -> deploy
2. Verify the complete chain is auditable:
   - From: typed provenance records from predecessor steps
   - Through: build provenance, SBOM, image signature
   - To: signed deploy attestation with verified outcome

---

## Formats and standards alignment

| Concern | Format | Standard |
|---------|--------|----------|
| Attestation envelope | DSSE | in-toto v1 |
| Payload type | `application/vnd.strike.attestation+json` | Custom (registered) |
| Signature algorithm | ECDSA P-256 SHA-256 | RFC 6979 |
| Key format | PKCS#8 PEM / cosign encrypted | Sigstore convention |
| OCI storage | Referrer artifact | OCI 1.1 |
| Schema | CUE (source of truth) + JSON Schema (export) | -- |
| Source identity | Method-dependent (GPG/SSH/gitsign) | No standard |
| Commit signing | Native git signatures | Git CMS/PKCS7 |

The `payloadType` in DSSE is strike-specific. If interoperability
with in-toto verifiers is desired later, the attestation can be
wrapped in an in-toto Statement (`_type: https://in-toto.io/Statement/v1`)
with a custom predicate type. This is a backward-compatible change.
