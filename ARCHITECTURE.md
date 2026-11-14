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
| **Hermetic builds**          | no          | yes        | yes        | yes [10]        |
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
6. Requires deterministic timestamps (fixed in image content,
   SOURCE_DATE_EPOCH for SBOMs) and elimination of non-deterministic inputs.
   See "Reproducible builds" below.
7. No integrity verification of the binary being invoked.
8. Go module checksum database (sum.golang.org) provides transparent,
   append-only verification of all dependencies.
9. Socket-level attacks operate below application monitoring, leaving minimal
   forensic traces.
10. Hermetic except for declared peers: a step that declares no peer has no
    egress at all, and a declared peer is reached only through strike's
    mediation, which records the connection (ADR-022, ADR-028, ADR-033).

### How strike combines the approaches

Security-critical operations run as **native Go code** within the controller
process: `go-containerregistry` for OCI image assembly, `cyclonedx-go` and
`spdx/tools-golang` for SBOM generation (CycloneDX and SPDX 2.3), strike's own
Fulcio, Rekor v2, and RFC3161 TSA clients for keyless signing, its own
verifier for `strike verify`, and the contract's generated types for the
in-toto statements. `sigstore-go` is a test-only dependency, the
cross-validation oracle the produced bundles and the verifier are checked
against (ADR-040 D2).

Build workload execution uses the **container engine API** over Unix socket or
TLS-secured TCP, treating the engine as an untrusted worker. The controller
never trusts the engine's self-reported digests -- it independently verifies
all artifacts after retrieval.

**os/exec is prohibited.** The hard invariant: the controller process never
spawns subprocesses. State capture, HTTP probes, and other workload operations
run inside containers via the Engine API; acts the controller must be able to
attest as its own, such as the registry push, are API calls it makes directly.

## Trust boundaries

```
+-----------------------------------------------------+
| TRUSTED: strike controller process                  |
|                                                     |
|  +-----------+ +----------+ +-------------------+   |
|  | go-       | | keyless  | | CycloneDX + SPDX  |   |
|  | container | | signing  | | SBOM generation   |   |
|  | registry  | | (P-256)  | | (in-process)      |   |
|  +-----------+ +----------+ +-------------------+   |
|                                                     |
|  +----------------------------------------------+   |
|  | In-toto statements + Fulcio, Rekor v2, TSA   |   |
|  +----------------------------------------------+   |
+--------------------+--------------------------------+
                     | TLS (TCP) or Unix socket
                     v
+-----------------------------------------------------+
| UNTRUSTED: container engine (podman)                |
|                                                     |
|  Build steps run with:                              |
|    --cap-drop=ALL --read-only                       |
|    --security-opt=no-new-privileges                 |
|    --userns=keep-id --tmpfs=/tmp:noexec,nosuid      |
|    --network=pasta (egress to declared peers only)  |
+-----------------------------------------------------+
```

The controller signs only digests it has independently verified. The engine is
treated as an untrusted worker that may return incorrect data. This mirrors the
Tekton Chains architecture: a separate controller observes build results,
verifies them, and produces signed attestations.

## Connection modes

strike supports two connection modes to the container engine:

- **Unix socket** -- acceptable for local and development builds. Authentication
  relies on filesystem permissions (the socket file's owner and mode). Without
  `CONTAINER_HOST`, strike connects to the first socket that exists of
  `$XDG_RUNTIME_DIR/podman.sock` (served by a long-running `podman system
  service` on the reference endpoint, ADR-055 D8), rootless podman's default
  `$XDG_RUNTIME_DIR/podman/podman.sock`, `/run/user/<uid>/podman/podman.sock`,
  and the rootful `/run/podman/podman.sock`.

- **TLS-secured TCP** -- mandatory for connections to remote container engines.
  TLS 1.3 with server certificate verification is always required: strike
  checks the engine's certificate against `CONTAINER_TLS_CA` when it is set,
  otherwise against the system trust store. mTLS (mutual certificate
  authentication) is optional: with `CONTAINER_TLS_CERT` and
  `CONTAINER_TLS_KEY` set, the controller presents a client certificate, which
  the engine verifies against its own trust configuration. strike refuses to
  connect over unencrypted TCP.

### Engine connection in the sealed attestation

The control plane records how it reached the engine in the sealed layer of the
deploy attestation (`sealed.engine`, and `externalParameters.engine` of the
SLSA provenance): the connection type (`unix`, `tls`, or `mtls`), how the
engine's server certificate was trusted (`pinned` or `system`), that
certificate's fingerprint, subject, and issuer, and over mTLS the controller's
own client-certificate fingerprint and subject. The control plane reads these
facts off the connection itself. They allow downstream consumers to verify the
security posture under which an artifact was built and to enforce policies such
as "production images must be built over mTLS-secured connections."

## AAA on the engine connection

**Authentication.** For TCP connections, TLS is mandatory and mTLS is optional.
Unix socket connections rely on filesystem permissions. strike refuses to connect
over unencrypted TCP.

**Authorization.** strike does not attempt to restrict which API calls it makes
to the engine -- the engine grants full access to whoever connects. Instead,
strike restricts what it *asks* the engine to do: every step container, run
or deploy, receives the same hardened security profile, including the same
peer-driven network opt-in (see [ADR-022](docs/ADR-022-network-opt-in-as-peer-list.md)).

**Accounting.** With `STRIKE_AUDIT=1`, an `http.RoundTripper` wrapper logs every
engine API request to stderr with method, path (which carries the container and
image identifiers), response status, and duration, never a request body. The
audit trail is forensic data if the engine is compromised; it is not part of the
attestation.

## Reproducible builds

strike achieves reproducible OCI image assembly through four mechanisms:

1. **Deterministic timestamps.** No timestamp depends on when strike runs.
   SBOM metadata uses `SOURCE_DATE_EPOCH` when set, otherwise Unix epoch 0,
   the convention established by Debian, apko, and ko. Image content carries
   fixed times instead: every file in a layer strike writes has modification
   time Unix epoch 0, each history entry strike appends carries the zero time
   (`0001-01-01T00:00:00Z`, the go-containerregistry default), and an assembled
   image keeps the creation time of its digest-pinned base image's config. An
   output wrapped as an image has no base and carries the zero time.

2. **Content-addressed everything.** Base images are digest-pinned. File layers
   are constructed from content, not filesystem metadata. The spec hash is a
   Merkle tree over image digest, arguments, environment, and the spec hashes
   of the producing steps -- fully computable before execution, and free of
   file sizes. The artifact size strike records (the `dev.strike.content-size`
   annotation a cache hit restores it from) is a logical byte count (equivalent
   to ```du -sb```), not on-disk allocation (plain ```du -s```). This is
   required for reproducibility across filesystems with different block sizes.

3. **No non-deterministic inputs.** Pack steps do not execute commands inside
   the image (no `RUN`). They assemble layers from typed file entries with
   explicit modes, UIDs, and GIDs.

4. **Verification contract.** A registry deploy may name a second pack step in
   `reproducedBy`, whose image must be byte-identical to the deploy's image
   arm. The control plane compares the two manifest digests as the first act of
   the deploy and fails it, before any capture, push, or signature, when they
   differ (ADR-009).

## IAN properties and failure modes

IAN = Integrity, Authenticity, Non-Repudiation from the CIAAN model.

| Attack scenario              | Integrity | Authenticity | Non-Repudiation | Detection     |
|------------------------------|-----------|--------------|-----------------|---------------|
| Engine returns wrong digest  | preserved | preserved    | preserved       | Controller re-verifies via go-containerregistry |
| Engine injects layer         | broken    | broken       | preserved [R]   | Reproducibility check; Rekor log mismatch |
| Signing key exfiltrated      | preserved | broken       | broken          | No persistent key (keyless, ADR-043); Rekor logs every signature [K] |
| OIDC token intercepted       | preserved | broken       | broken          | Token lifetime at most fifteen minutes, enforced (ADR-058 D4); Fulcio CT |
| Socket hijacked (Unix)       | broken    | broken       | broken          | Filesystem monitoring; audit log gaps |
| Socket hijacked (TCP)        | preserved | preserved    | preserved       | TLS prevents connection; mTLS when enabled |
| Dependency compromise        | broken    | broken       | partial [S]     | govulncheck; sum.golang.org audit trail |
| Lane definition tampered     | broken    | broken       | preserved [G]   | Git commit signatures; lane digest in attestation |

[R] Rekor transparency log entry survives engine compromise.
[S] Go checksum database provides post-incident detection.
[G] Git history provides attribution.
[K] ADR-043 retired keyed signing: the ECDSA P-256 signing key is
    ephemeral, generated per signature and discarded, so there is no
    persistent key to exfiltrate and "key rotation" does not apply.
    Authenticity and non-repudiation break only if an attacker also
    obtains the OIDC identity that authorizes Fulcio issuance (see "OIDC
    token intercepted"); any forged signature is itself recorded in the
    Rekor transparency log.

## Non-repudiation chain

The full non-repudiation chain for a strike-produced artifact:

1. **Lane definition** -- committed to Git with a signed commit.
2. **Source inputs** -- fetched by a step inside its container; strike hashes
   no source tree of its own. A later step consumes the fetched source as that
   step's output, bound through the producer's spec hash, and the step's
   provenance file records where the source came from (see "Source provenance"
   below). When strike wraps an output, a symlink whose target escapes the
   wrapped subtree is an error.
3. **Build execution** -- each step runs in a hardened container through the
   engine API, and its result enters the chain as content-addressed outputs
   bound to its spec hash. strike logs one line per step and, with
   `STRIKE_AUDIT=1`, every engine call to stderr; neither log is signed.
4. **Artifact provenance** -- each artifact in the deploy attestation carries a
   full `record.#Artifact`: the content-addressed manifest digest (computed
   by the controller via `go-containerregistry`) and, when one was
   generated, the SBOM record (format + digest). The signature, certificate,
   and Rekor entry live in the keyless DSSE bundle, not in this record.
   Schema: `contract/record/record.cue`.
5. **SBOM** -- generated in-process by cataloging the assembled image's
   flattened filesystem (npm lockfiles, dpkg status, Go buildinfo). Both
   CycloneDX and SPDX 2.3 are emitted as OCI referrers bound to the
   artifact's digest. The SBOM is a sealed-layer claim: produced from
   bytes the control plane holds, not from engine-relayed content.
6. **Attestation and signature** -- the deploy attestation is projected into
   three in-toto statements (SLSA provenance, engine-context, informational)
   whose subject names the manifest digest. Each is signed as a DSSE envelope
   (Dead Simple Signing Envelope, the in-toto v1 standard) by an ephemeral
   ECDSA P-256 key that Fulcio certifies against the lane's OIDC identity,
   logged in Rekor v2 as a `hashedrekord` entry over the signed digest, and
   timestamped by an RFC3161 TSA. The certificate, the log entry, and the
   timestamp ride in the statement's sigstore bundle, never in a payload
   (ADR-013), and each bundle is published as an OCI referrer of the artifact.
7. **Deploy state** -- digests of the pre-state and post-state captures, in
   the deploy attestation. The raw capture output is not recorded, and strike
   neither detects drift nor acts on it (ADR-016).

### End-to-end attestation

Source provenance and attestation signing close the original open ends:

- **Source provenance** records where a step's source came from. A step
  that fetches source declares a provenance file, and strike validates
  it at step exit against the record of its declared type: the URI and
  the commit of a git source, or the URI and the digest of a tarball,
  an OCI artifact or a URL. Git runs in the step's container (preserving
  the no-exec.Command invariant). The record is container-asserted, so
  the deploy attestation carries it as informational, and no
  verification gates on it (ADR-037).

- **Attestation signing** wraps the deploy attestation in DSSE
  envelopes signed keylessly: an ephemeral key certified by Fulcio
  against the lane's declared OIDC identity, logged in a Rekor v2
  transparency log as `hashedrekord` entries over the signed digest and
  timestamped by an RFC3161 TSA.
  The collect-model attestation is projected into three in-toto
  statements -- SLSA provenance, engine-context, and informational --
  along the boundary between the sealed and the engine-dependent layer.
  Verification is offline, without contacting strike or the original engine
  (ADR-039, ADR-040).

Together, these complete the chain from developer keystroke to verified
production state.
