# strike

Reproducible, rootless CI/CD lanes. No shell. No root. No local toolchain.

**Please note that the Strike project is still in the pre-beta and pre-production phase.**
Breaking changes are acceptable and do not need to be mentioned.
The bar the project must clear to leave that phase is recorded in [docs/BETA-DEFINITION-OF-DONE.md](docs/BETA-DEFINITION-OF-DONE.md).

We are developing our tool architecture based on real-world use cases with
the aim of creating a tool that operates according to a few principles
to support software attestation and provenance tracing -- end-to-end when
the container engine shares the controller's trust domain (local rootless,
or remote with an attested TCB), best-effort when it does not (see
[SECURITY.md](SECURITY.md#attestation-soundness-best-effort-vs-end-to-end)).

This will also systematically reduce the attack surface for modern software
supply-chain attacks.

See also: [DESIGN-PRINCIPLES.md](DESIGN-PRINCIPLES.md)

## What is strike?

strike produces verifiable supply-chain provenance for the artifacts it
builds. Each lane run yields a signed, transparency-logged attestation that
records what was built, from which digest-pinned inputs, in what runtime, and
under which declared identity -- a record a consumer can check offline,
without trusting strike or the engine that ran the work. In an increasingly
containerized world the artifact's own contents are the input that matters,
so strike catalogs the image it assembled in-process and emits it as a
first-class CycloneDX and SPDX 2.3 SBOM bound to the artifact's digest.

The execution model exists to keep that attestation sound. Every step runs in
a pinned, digest-verified OCI image with no shell, no privilege escalation,
and no network unless its peers are declared; the controller spawns no
subprocesses and holds no long-lived keys. Mutable references are rejected
before the DAG is built, and byte-identical inputs must produce byte-identical
outputs, so an independent implementation can re-derive the result and check
it. Claims the controller can vouch for itself are kept separate from claims
only the engine can make, so a verifier always knows which survive without
trusting the engine.

Lanes are declared in YAML, validated against a CUE schema, and executed as a
content-addressable DAG. Outputs and their attestations are stored as OCI
artifacts in any standard registry.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the security architecture, SLSA 3
compliance analysis, and trust boundary model.

## Prerequisites

You need exactly two things:

1. **Podman (rootless) with socket enabled** -- the only host dependency.
   Enable the socket: `systemctl --user enable --now podman.socket`
2. **A git-capable IDE** (e.g. VS Code, JetBrains) -- for cloning and editing
   the repository. You do not need a local `git` CLI; your IDE handles that.

Your host must satisfy the standard rootless podman requirements:

- **subuid/subgid** configured for the calling user (minimum 65 536 entries).
  Check with `cat /etc/subuid` -- you should see a line like
  `youruser:100000:65536`.
- **`kernel.unprivileged_userns_clone=1`** on Linux (most distributions set
  this by default).

These are prerequisites for rootless podman generally, not specific to strike.

That's it. No Go toolchain, no `make`, no `npm`, no CI agent. The entire build
happens inside containers.

## Bootstrap

strike builds itself, and the bootstrap proves that build reproducible. It
starts from a single Containerfile fetched by pinned commit hash from GitHub.
No stage of the bootstrap carries a container engine: strike is always a
client of the one engine you already run.

The bootstrap is a workstation proof against the local sigstore harness in
`test/sigstore-local`: it deploys to the harness registry and signs under the
harness keyless chain. Bring the harness up from a clone of this repository
first (`make -C test/sigstore-local up`), then build stage_1 from the clone's
root:

```sh
GIT_COMMIT=0fa9af446f422bd51da4258b44f4bc8893bf9475

podman build -t strike:stage_1 \
  --build-arg GIT_COMMIT=${GIT_COMMIT} \
  --build-context harness=test/sigstore-local/pki \
  https://raw.githubusercontent.com/istr/strike/${GIT_COMMIT}/bootstrap/Containerfile
```

This builds the stage_1 image from a fully pinned source: the Containerfile is
fetched by commit SHA, and the base images are pinned by digest. Inside the
build, git fetches the exact commit, the strike binary is compiled, and the
bootstrap lane is rendered from its template `bootstrap/lane.cue`: the commit
the build fetched becomes the lane's source revision, and the harness root
from the `harness` build context anchors the harness endpoints. The stage_1
image carries the binary and the rendered lane, and nothing else.

stage_1 runs as a sibling of its own steps:

```sh
SIGSTORE_ID_TOKEN=$(make -s -C test/sigstore-local token) \
podman run --rm \
  --userns=keep-id:uid=65532,gid=65532 \
  --network=host \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v "$XDG_RUNTIME_DIR/podman.sock:/run/podman/podman.sock" \
  -e CONTAINER_HOST=unix:///run/podman/podman.sock \
  -e SIGSTORE_ID_TOKEN \
  strike:stage_1
```

Your engine starts it with the engine socket bound in and named through
`CONTAINER_HOST`, host networking, and the keep-id mapping that places your
user on the image's user (plain `--userns=keep-id` leaves the process on the
image's user, which cannot open your socket). The harness token is minted for
this one run. strike drives that same engine to run the bootstrap lane:

1. **source** -- fetches the commit in a digest-pinned git image; its only
   peer is `github.com`.
2. **fetch** -- downloads the Go modules in the pinned Chainguard Go image.
   It is the only other step with network: `proxy.golang.org`, and
   `storage.googleapis.com`, where the proxy redirects some module archives.
   `go.sum` covers every module, so a gap fails the step.
3. **generate** -- generates the CUE-derived Go sources, without network.
4. **build-binary** -- compiles the strike binary with `CGO_ENABLED=0` and
   the toolchain locked to the image, without network.
5. **build-image** -- packs the binary into an OCI image based on
   `chainguard/static`. This image is stage_2.
6. **build-binary-2**, **build-image-2** -- the same build and pack again, in
   the same run, with the cache bypassed. This image is stage_3.
7. **publish** -- a registry deploy of stage_2 to the harness registry,
   signed under the harness keyless chain. Its `reproducedBy` gate names
   stage_3: before anything is pushed, the deploy asserts that stage_2 and
   stage_3 are byte-identical and fails on a mismatch.

A passing run logs `GATE   reproducedBy: build-image and build-image-2 built
sha256:...` and then `OK     publish ->
registry.127.0.0.1.sslip.io:5443/istr/strike@sha256:...`. Publishing to a
public registry under the public sigstore chain is not part of the bootstrap
yet.

The in-lane comparison proves that strike's orchestration is deterministic.
Two further checks prove more: the released strike, rebuilding the same commit
on another host, must reach the same image digest, and a plain build of the
binary in the pinned Go image, without strike, must match the binary in the
released image. None of the three defends against a compromised compiler; the
Go toolchain is a fixed, externally verified input. See
[ADR-009](docs/ADR-009-bootstrap-reproducibility-proof.md).

## How it works

### Lane schema

Lanes are YAML files validated against an embedded CUE schema. Every
external container image must be SHA-256 pinned:

```yaml
resolver:
  adn: dns.example.com
  ip: 198.51.100.1
  trust:
    cert: "<base64 DER of the resolver's root certificate>"
oidc:
  issuer: "https://idp.example.com"
  audience: "strike"
  identity: "strike@example.com"
  trust:
    cert: "<base64 DER of the identity provider's root certificate>"
keyless:
  endpoints:
    fulcio:
      url: "https://fulcio.example.com"
      trust:
        cert: "<base64 DER of the Fulcio root certificate>"
    rekor:
      url: "https://rekor.example.com"
      trust:
        cert: "<base64 DER of the Rekor root certificate>"
    tsa:
      url: "https://tsa.example.com"
      trust:
        cert: "<base64 DER of the TSA root certificate>"
steps:
  - id: source
    image: docker.io/library/alpine/git@sha256:abc123...
    args: [git, clone, --depth, "1", "https://example.com/repo.git", /out/tree]
    peers:
      - type: https
        host: example.com
        trust:
          cert: "<base64 DER of the peer's root certificate>"
    outputs:
      - { id: tree, type: directory, path: /out/tree }
    provenance:
      type: git
      path: /out/provenance.json

  - id: build
    image: cgr.dev/chainguard/go@sha256:def456...
    args: [go, build, -C, /src, -o, /out/binary, .]
    inputs:
      - { name: tree, from: source.tree, mount: /src }
    outputs:
      - { id: binary, type: file, path: /out/binary }
```

Each `cert:` value above is produced with:

```sh
openssl x509 -in root.crt -outform DER | base64 -w0
```

A step reaches the network only through the peers it declares. Each
peer carries its trust anchor: for HTTPS the certificate itself, for
SSH the known_hosts entries, for an OCI registry the image digest. A
step that declares no peer gets an empty egress allowlist and every
connection attempt is refused. See
[ADR-022](docs/ADR-022-network-opt-in-as-peer-list.md) and
[ADR-028](docs/ADR-028-step-container-egress-mediation.md).

### Image references

Steps resolve their execution image in one of two ways:

| Field           | Use case                  | Pinning                        |
|-----------------|---------------------------|--------------------------------|
| `image`         | External registry image   | Must contain `@sha256:` digest |
| `imageFromStep` | Output of a previous step | Digest extracted at load time  |

`imageFromStep` names an earlier step whose output is an image; an image
output is addressed by its producing step alone. The executor loads the tar
into the local container store and pins the image by its manifest digest,
creating an implicit DAG edge:

```yaml
  - id: check-built
    imageFromStep: build-image
    args: [/usr/bin/strike, validate, /src/lane.yaml]
    inputs:
      - from: { step: src, output: tree }
        mount: /src
```

### Content-addressable caching

Each step's cache key is a spec hash -- a Merkle tree over:
- the image digest
- the step arguments
- input hashes (spec hashes of producing steps, not content)
- environment variables

Cache lookup is local-first, then remote. Cache artifacts are stored as OCI
images in any standard registry.

### No shell

strike lanes do not use shell interpreters. Steps specify an image and an
args array. There are no `run:` blocks, no `bash -c`, no string interpolation.
Secrets are passed as environment variables, never written to process arguments.

## Project structure

```
cmd/strike/main.go               CLI entry point (run, validate, dag, verify)
contract/
  lane/lane.cue                   CUE schema (source of truth)
internal/
  container/
    engine.go                     Engine interface, types, socket detection
    transport.go                  Unix socket and HTTPS transport
    podman.go                     Podman libpod REST API implementation
  lane/
    cue_types_lane_gen.go         Generated Go types (generated, not in git)
    parse.go                      YAML parsing and CUE validation
    dag.go                        DAG construction and topological sort
    state.go                      Artifact and step result tracking
    digest.go                     Content hashing and cache key computation
    deploy_method.go              DeployMethod accessor helpers
    secret.go                     Secret resolution
  executor/
    podman.go                     Container execution via Engine API
    validate.go                   Output validation (magic bytes, size bounds)
    pack.go                       OCI image assembly (native Go, no container)
    catalog.go                    Native SBOM cataloger (CycloneDX + SPDX 2.3)
    flatten.go                    In-memory image flattening (image -> fs.FS)
  registry/
    cache.go                      Spec hashing and cache tagging
    client.go                     Registry operations (Engine API, go-containerregistry)
  deploy/
    deploy.go                     Deploy with mandatory state attestation
bootstrap/Containerfile           Self-contained bootstrap image
bootstrap/lane.cue                Bootstrap lane template
```

## Development

For working on strike itself (not for using it), you need Go 1.26+,
golangci-lint 2.x, and govulncheck. Every change must pass before merge:

```sh
golangci-lint run ./...                                         # lint and security
go test -race -coverprofile=coverage.out -covermode=atomic ./...  # tests
govulncheck ./...                                                # vulnerability scan
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the complete code quality,
security, and style guidelines.

AI coding agents should read [AGENTS.md](AGENTS.md) before making changes.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, vulnerability reporting,
and design principles.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
