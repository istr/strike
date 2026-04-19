# Architecture

strike is a rootless, shell-free, container-native CI/CD executor. This
document describes the security architecture, the trust model between strike
and the container engine, and how the design maps to SLSA Build Level 3.

## Executor architecture: why API, not exec

strike communicates with the container engine exclusively via REST API over
Unix socket or TLS-secured TCP. There are zero `os/exec` imports in the
codebase. This is a security invariant, not a style preference.

Three executor approaches exist for container-native CI/CD tools. strike chose
API communication combined with in-process library integration because this is
the only combination that achieves SLSA Build Level 3 without extraordinary
hardening measures.

### SLSA Build Level compliance matrix

| Requirement                  | exec binary | Go library | Socket/API | strike (hybrid) |
|------------------------------|:-----------:|:----------:|:----------:|:---------------:|
| **L1** Provenance exists     | yes         | yes        | yes        | yes             |
| **L2** Signed provenance     | weak [1]    | yes        | yes        | yes             |
| **L3** Key isolation         | no [2]      | yes        | yes [3]    | yes             |
| **L3** Build isolation       | no [4]      | weak [5]   | yes        | yes             |
| **Hermetic builds**          | no          | yes        | yes        | yes             |
| **Reproducible builds**      | possible    | yes        | possible   | yes [6]         |
| **Supply chain auditability**| weak [7]    | yes [8]    | weak [9]   | yes             |

Notes:

1. Shared process environment blurs trust boundary between orchestrator and
   tool binary.
2. Subprocess shares environment variables, including OIDC tokens and signing
   key material.
3. Only if the socket is properly secured (TLS mandatory for TCP, mTLS
   optional; filesystem permissions for Unix).
4. Binary replacement via PATH hijacking, LD_PRELOAD, or CONTAINER_HOST
   poisoning.
5. Single process boundary -- a compromised library has full access.
6. Requires deterministic timestamps (SOURCE_DATE_EPOCH) and elimination of
   non-deterministic inputs. See "Reproducible builds" below.
7. No integrity verification of the binary being invoked.
8. Go module checksum database (sum.golang.org) provides transparent,
   append-only verification of all dependencies.
9. Socket-level attacks operate below application monitoring, leaving minimal
   forensic traces.

### How strike combines the approaches

Security-critical operations use **native Go libraries** within the controller
process: `go-containerregistry` for OCI image assembly, `sigstore-go` (planned)
for signing and verification, `cyclonedx-go` for SBOM generation, and
`in-toto/attestation` (planned) for provenance construction.

Build workload execution uses the **container engine API** over Unix socket or
TLS-secured TCP, treating the engine as an untrusted worker. The controller
never trusts the engine's self-reported digests -- it independently verifies
all artifacts after retrieval.

**os/exec is prohibited.** The hard invariant: the controller process never
spawns subprocesses. State capture, kubectl, HTTP probes, and all other
external operations run inside containers via the Engine API.

## Trust boundaries

```
+-----------------------------------------------------+
| TRUSTED: strike controller process                  |
|                                                     |
|  +-----------+ +----------+ +-------------------+   |
|  | go-       | | ECDSA    | | CycloneDX SBOM    |   |
|  | container | | signing  | | generation        |   |
|  | registry  | | (P-256)  | |                   |   |
|  +-----------+ +----------+ +-------------------+   |
|                                                     |
|  +----------------------------------------------+   |
|  | Attestation construction + Rekor submission  |   |
|  +----------------------------------------------+   |
+--------------------+--------------------------------+
                     | TLS (TCP) or Unix socket
                     v
+-----------------------------------------------------+
| UNTRUSTED: container engine (podman)                |
|                                                     |
|  Build steps run with:                              |
|    --cap-drop=ALL --read-only --network=none        |
|    --security-opt=no-new-privileges                 |
|    --userns=keep-id                                 |
+-----------------------------------------------------+
```

The controller signs only digests it has independently verified. The engine is
treated as an untrusted worker that may return incorrect data. This mirrors the
Tekton Chains architecture: a separate controller observes build results,
verifies them, and produces signed attestations.

## Connection modes

strike supports two connection modes to the container engine:

- **Unix socket** -- acceptable for local and development builds. Authentication
  relies on filesystem permissions (the socket file's owner and mode). This is
  the default for rootless podman (`$XDG_RUNTIME_DIR/podman/podman.sock`).

- **TLS-secured TCP** -- mandatory for connections to remote container engines.
  TLS (server certificate verification) is always required; mTLS (mutual
  certificate authentication) is optional. When mTLS is enabled, the controller
  presents a client certificate and the engine presents a server certificate,
  both verified against a shared CA. strike refuses to connect over unencrypted
  TCP.

### TLS metadata in signature annotations

The connection security context is recorded in the signature annotation payload.
This includes whether TLS or mTLS was used, certificate fingerprints (when
available), and the connection type (unix or tcp). This metadata allows
downstream consumers to verify the security posture under which an artifact was
built and to enforce policies such as "production images must be built over
mTLS-secured connections."

## AAA on the engine connection

**Authentication.** For TCP connections, TLS is mandatory and mTLS is optional.
Unix socket connections rely on filesystem permissions. strike refuses to connect
over unencrypted TCP.

**Authorization.** strike does not attempt to restrict which API calls it makes
to the engine -- the engine grants full access to whoever connects. Instead,
strike restricts what it *asks* the engine to do: all step containers receive
the hardened security profile. Deploy containers receive the same profile with
explicit network exceptions.

**Accounting.** Every API request is logged with method, path, container ID,
image digest, and response status via a `http.RoundTripper` wrapper. This audit
trail feeds into the attestation record and provides forensic data if the engine
is compromised.

## Reproducible builds

strike achieves reproducible OCI image assembly through four mechanisms:

1. **Deterministic timestamps.** SBOM metadata, OCI config timestamps, and
   layer modification times use `SOURCE_DATE_EPOCH` when set, otherwise Unix
   epoch 0. This follows the convention established by Debian, apko, and ko.

2. **Content-addressed everything.** Base images are digest-pinned. File layers
   are constructed from content, not filesystem metadata. The spec hash is a
   Merkle tree over image digest, arguments, environment, input hashes, and
   source hashes -- fully computable before execution.

3. **No non-deterministic inputs.** Pack steps do not execute commands inside
   the image (no `RUN`). They assemble layers from typed file entries with
   explicit modes, UIDs, and GIDs.

4. **Verification contract.** When `reproducible: true` is set on a pack step,
   strike verifies reproducibility by re-assembling the image from the same
   inputs and comparing manifest digests. A mismatch aborts the lane.

## IAN properties and failure modes

IAN = Integrity, Authenticity, Non-Repudiation from the CIAAN model.

| Attack scenario              | Integrity | Authenticity | Non-Repudiation | Detection     |
|------------------------------|-----------|--------------|-----------------|---------------|
| Engine returns wrong digest  | preserved | preserved    | preserved       | Controller re-verifies via go-containerregistry |
| Engine injects layer         | broken    | broken       | preserved [R]   | Reproducibility check; Rekor log mismatch |
| Signing key exfiltrated      | preserved | broken       | broken          | Rekor certificate transparency; key rotation |
| OIDC token intercepted       | preserved | broken       | broken          | Short token lifetime (seconds); Fulcio CT |
| Socket hijacked (Unix)       | broken    | broken       | broken          | Filesystem monitoring; audit log gaps |
| Socket hijacked (TCP)        | preserved | preserved    | preserved       | TLS prevents connection; mTLS when enabled |
| Dependency compromise        | broken    | broken       | partial [S]     | govulncheck; sum.golang.org audit trail |
| Lane definition tampered     | broken    | broken       | preserved [G]   | Git commit signatures; lane digest in attestation |

[R] Rekor transparency log entry survives engine compromise.
[S] Go checksum database provides post-incident detection.
[G] Git history provides attribution.

## Non-repudiation chain

The full non-repudiation chain for a strike-produced artifact:

1. **Lane definition** -- committed to Git with a signed commit.
2. **Source inputs** -- hashed through `os.Root` scoped reads, digests recorded
   in spec hash. Symlinks in source trees are rejected (both valid and broken)
   to prevent non-deterministic hashing and implicit references outside the
   source directory.
3. **Build execution** -- container create/start/wait/remove logged with
   timestamps and container IDs.
4. **Artifact provenance** -- each artifact in the deploy attestation carries a
   full `#SignedArtifact` record: content-addressed digest (computed by the
   controller via `go-containerregistry`), signature metadata, SBOM digest,
   and Rekor transparency log entry. Schema: `specs/artifact.cue`.
5. **SBOM** -- generated in-process from Go build info and base image referrers.
   The SBOM digest is recorded in the artifact's `#SBOMRecord`.
6. **Signature** -- ECDSA P-256 over manifest digest, recorded in Rekor
   transparency log. Signing metadata is captured in `#SignatureRecord`.
7. **Attestation** -- SLSA Provenance predicate with all inputs, parameters,
   and outputs, signed as a DSSE envelope (Dead Simple Signing Envelope,
   the in-toto v1 standard) and submitted to the Rekor transparency log
   as a `dsse` entry. The `att.Rekor` field is unsigned metadata -- it
   proves the signing event was logged but is not covered by the DSSE
   signature. Verifiers must strip the `rekor` field before checking
   the DSSE signature.
8. **Deploy state** -- pre-state and post-state snapshots with drift detection.

### End-to-end attestation

Source provenance and attestation signing close the original open ends:

- **Source provenance** enriches deploy attestations with git commit
  metadata: commit range, signer identities (GPG, SSH, or gitsign),
  and a boolean `all_signed` flag for policy gates. Git runs in a
  container (preserving the no-exec.Command invariant).

- **Attestation signing** wraps the deploy attestation in a DSSE
  envelope signed with the same cosign key that signs image manifests.
  The signed DSSE envelope is submitted to Rekor as a `dsse` entry,
  providing independent third-party timestamping of the signing event.
  This completes the Rekor chain: each artifact's signature has a
  transparency log entry (hashedrekord), and the attestation that
  references those artifacts also has a transparency log entry (dsse).

Together, these complete the chain from developer keystroke to verified
production state. The design is documented in
`docs/END-TO-END-ATTESTATION.md`.
