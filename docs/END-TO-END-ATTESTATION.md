# End-to-end attestation: source provenance, outcome signing, and integration tests

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

## Part 1: Source provenance in attestations

### What to capture

When a lane has source mounts, strike can extract git metadata by
running git in a container (consistent with the no-exec.Command
invariant). The attestation gains a `source` field:

```json
{
  "deploy_id": "a1b2c3d4e5f67890",
  "source": {
    "commit": "abc123def456...",
    "ref": "refs/heads/main",
    "range": {
      "from": "previous_deploy_commit_or_tag",
      "to": "abc123def456..."
    },
    "signers": [
      {
        "commit": "abc123...",
        "identity": "dev@example.com",
        "method": "ssh",
        "fingerprint": "SHA256:...",
        "verified": true
      },
      {
        "commit": "def456...",
        "identity": "other@example.com",
        "method": "gitsign",
        "oidc_issuer": "https://accounts.google.com",
        "verified": true
      }
    ],
    "unsigned_commits": ["789abc..."],
    "all_signed": false
  },
  "artifacts": { ... },
  "pre_state": { ... },
  "post_state": { ... }
}
```

### Design decisions

**Git runs in a container.** No exec.Command, no exception. Use a
digest-pinned git image (e.g., `cgr.dev/chainguard/git@sha256:...`).
The source directory is bind-mounted read-only. The git command
extracts commit metadata and signature verification status as JSON.

**The signer list is not a new step type.** It is an automatic
enrichment of the deploy attestation when the lane includes source
mounts. Strike runs the git container internally as part of
`deploy.Execute()`, similar to how state capture runs containers.

**Verification is best-effort.** If the git image is not available,
or if the repo has no signatures, the `source` field records what
it found (including `unsigned_commits`). The `all_signed` flag lets
policies gate on signature completeness without parsing individual
entries.

**Identity is method-dependent.** GPG signatures expose key
fingerprints. SSH signatures expose key fingerprints. Gitsign
(Sigstore) signatures expose OIDC identity and issuer. The
`method` field disambiguates.

### CUE schema extension (attestation.cue)

```cue
#SourceProvenance: {
    // commit is the HEAD commit hash that produced the build.
    commit: =~"^[a-f0-9]{40}$"

    // ref is the git ref (branch or tag) at build time.
    ref: string

    // range is the commit range since the last deploy (optional).
    range?: {
        from: =~"^[a-f0-9]{40}$"
        to:   =~"^[a-f0-9]{40}$"
    }

    // signers lists verified commit signatures in the range.
    signers: [...#CommitSigner]

    // unsigned_commits lists commit hashes without signatures.
    unsigned_commits: [...=~"^[a-f0-9]{40}$"] | null

    // all_signed is true iff every commit in the range is signed.
    all_signed: bool
}

#CommitSigner: {
    commit:       =~"^[a-f0-9]{40}$"
    identity:     string
    method:       "gpg" | "ssh" | "gitsign" | "x509"
    fingerprint?: string
    oidc_issuer?: string
    verified:     bool
}
```

Add to `#Attestation`:
```cue
source?: #SourceProvenance
```

Optional because not every deploy step has source mounts.

### Implementation path

1. **Add `#SourceProvenance` to `specs/attestation.cue`**, run
   `make specs` to re-export JSON Schema.

2. **Add `SourceProvenance` struct to `internal/deploy/deploy.go`**,
   matching the CUE schema. Add `Source *SourceProvenance` field to
   `Attestation`.

3. **Add `captureSourceProvenance` method to `Deployer`** that:
   - Finds source mounts from the lane steps that produced the
     deployed artifacts (walk the DAG backwards)
   - Runs a git container with the source dir mounted read-only
   - Parses `git log --format='%H %G? %GK %GS' <range>` output
   - Builds the `SourceProvenance` struct

4. **Call from `Execute()`** between artifact resolution and deploy
   action. Non-fatal: if source capture fails, log a warning and
   proceed with `Source: nil`.

5. **Lane-level config** (optional, future): add a `source` block
   to the lane schema specifying the git image and commit range
   strategy. For the PoC, auto-detect from source mounts.

### Git signature parsing

The key git command (run inside a container):

```sh
git -C /src log --format='%H|%G?|%GK|%GS|%aE' HEAD~10..HEAD
```

Output format per line: `commit|status|key|signer|email`

Status codes (`%G?`):
- `G` = good GPG signature
- `B` = bad GPG signature
- `U` = good but untrusted GPG signature
- `X` = good but expired GPG signature
- `Y` = good but expired key GPG signature
- `N` = no signature
- `E` = cannot check signature

For SSH signatures (Git 2.34+), the same `%G?` flag works when
`gpg.format = ssh` is configured, and `%GK` contains the SSH key
fingerprint.

For gitsign, `git verify-commit <hash>` returns the OIDC identity
from the Fulcio certificate. Parsing requires `gitsign verify`
rather than raw git output.

**PoC simplification:** For the first implementation, parse `%G?`
and `%GK` only (covers GPG and SSH). Gitsign support can be added
later via `gitsign verify --certificate-identity` in a separate
container.

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
- Gated by `STRIKE_INTEGRATION=1` (per AGENTS.md)

**No external registry required.** Use `podman run -d registry:2`
to start a local OCI registry inside the test, or use Podman's
local store exclusively (load via `ImageLoad`, inspect via
`ImageInspect`). The local registry approach is more realistic.

### Test structure

Create `test/integration/` with:

```
test/integration/
    integration_test.go      # test gate, helpers
    source_test.go           # git provenance capture
    pack_test.go             # full pack pipeline
    deploy_test.go           # full deploy + attestation
    attestation_chain_test.go # end-to-end chain verification
    testdata/
        lane_build.yaml      # minimal build+pack lane
        lane_deploy.yaml     # deploy lane referencing packed image
        cosign_test.key      # deterministic test key (same as golden tests)
```

All tests use `package integration_test` and import the internal
packages. Gated by:

```go
func TestMain(m *testing.M) {
    if os.Getenv("STRIKE_INTEGRATION") == "" {
        fmt.Println("SKIP integration tests (set STRIKE_INTEGRATION=1)")
        os.Exit(0)
    }
    os.Exit(m.Run())
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

**TestSourceProvenance** -- exercises source capture:

1. Create a temp git repo in `t.TempDir()`
2. Configure git with a test GPG or SSH key
3. Make 3 signed commits and 1 unsigned commit
4. Invoke source provenance capture
5. Verify:
   - `source.commit` matches HEAD
   - `source.signers` has 3 entries with `verified: true`
   - `source.unsigned_commits` has 1 entry
   - `source.all_signed` is false

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

1. Create a git repo with signed commits
2. Write a lane with build + pack + deploy steps
3. Execute the full lane
4. Extract the deploy attestation
5. Verify the complete chain:
   - `source.commit` matches git HEAD
   - `source.signers` lists the test committer
   - `artifacts` maps to the packed image digest
   - `pre_state` captured before deploy
   - `post_state` captured after deploy
   - Attestation signature verifies with the cosign public key
   - Image in registry has referrers: SBOM, signature, attestation

This single test exercises every untested code path.

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

### Git test repo helper

```go
func createSignedRepo(t *testing.T, engine container.Engine) string {
    t.Helper()
    dir := t.TempDir()

    // Run git init + commits in a git container
    // Mount dir as /repo, mount test signing key
    // Execute: git init, git config, git commit --gpg-sign
    // Return dir path

    return dir
}
```

This uses the container engine (no exec.Command) to run git,
consistent with the project invariants.

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
5. Crossval vector: `testdata/crossval/sign/attestation_dsse.json`

This is self-contained, no new dependencies, no schema changes.

### Phase 2: Integration test infrastructure

1. Create `test/integration/` structure
2. Implement `startLocalRegistry` and engine helpers
3. Write `TestPackPipeline` (largest coverage impact)
4. Write `TestDeployAttestation` (exercises signed attestation)

### Phase 3: Source provenance

1. Extend `specs/attestation.cue` with `#SourceProvenance`
2. Add Go structs, wire into `Deployer.Execute()`
3. Implement `captureSourceProvenance` (git container)
4. Write `TestSourceProvenance` integration test

### Phase 4: End-to-end chain test

1. Write `TestEndToEndChain` combining all three
2. Verify the complete chain is auditable:
   - From: signed commit by known identity
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
