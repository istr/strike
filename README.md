# strike

Reproducible, rootless CI/CD lanes. No shell. No root. No local toolchain.

**Please note that the Strike project is still in the pre-beta and pre-production phase.**
Breaking changes are acceptable and do not need to be mentioned.

We are developing our tool architecture based on real-world use cases with
the aim of creating a tool that operates according to a few principles
to support end-to-end software attestation and provenance tracing.

This will also systematically reduce the attack surface for modern software
supply-chain attacks.

See also: [DESIGN-PRINCIPLES.md](DESIGN-PRINCIPLES.md)

## What is strike?

strike is a cloud-native lane executor that treats containers as the only
unit of computation. Every step runs in a pinned, digest-verified OCI image
with network disabled by default. There is no shell interpreter, no script
block evaluation, no implicit host dependency beyond a working rootless
container runtime.

Lanes are declared in YAML, validated against a CUE schema, and executed as
a content-addressable DAG. Outputs are cached as OCI artifacts in any standard
registry.

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

strike builds itself. The bootstrap process starts from a single Containerfile
fetched by pinned commit hash from GitHub -- no local clone required.

```sh
GIT_COMMIT=810b8812549187da2c73b0ac142f46db5d8b036c

podman build -t strike:stage_1 \
  --build-arg GIT_COMMIT=${GIT_COMMIT} \
  https://raw.githubusercontent.com/istr/strike/${GIT_COMMIT}/bootstrap/Containerfile
```

This builds the stage_1 image from a fully pinned source: the Containerfile is
fetched by commit SHA, and the base image is pinned by digest. Inside the
container, git fetches the exact commit, builds the strike binary, and produces
a self-contained executor image.

Then run the bootstrap lane:

```sh
podman run --userns=keep-id strike:stage_1
```

This executes the bootstrap lane (`lane.yaml`):

1. **build_binary** -- compiles the strike binary from source using a pinned
   Chainguard Go image with `CGO_ENABLED=0`.
2. **build_image** -- packs the binary into a signed OCI image based on
   `chainguard/static`.
3. **stage_2** -- runs `bootstrap/lace.yaml` inside `strike:stage_1` to rebuild
   the image from source, producing `stage_3`.
4. **compare** -- verifies that stage_2 and stage_3 produce identical images,
   proving the build is reproducible.
5. **publish** -- pushes the verified image to the registry.

## How it works

### Lane schema

Lanes are YAML files validated against an embedded CUE schema. Every
external container image must be SHA-256 pinned:

```yaml
steps:
  - name: source
    image: docker.io/library/alpine/git@sha256:abc123...
    args: [git, clone, --depth, "1", "https://example.com/repo.git", /out/tree]
    peers:
      - type: https
        host: example.com
        trust:
          mode: cert_fingerprint
          fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
    outputs:
      - { name: tree, type: directory, path: /out/tree }
    provenance:
      type: git
      path: /out/provenance.json

  - name: build
    image: cgr.dev/chainguard/go@sha256:def456...
    args: [go, build, -C, /src, -o, /out/binary, .]
    inputs:
      - { name: tree, from: source.tree, mount: /src }
    outputs:
      - { name: binary, type: file, path: /out/binary }
```

Steps run with `--network=none` by default. To opt into network
access, declare a `peers:` list with the trust anchor for each
peer (HTTPS cert fingerprint or CA bundle, SSH known_hosts, OCI
registry digest). See [ADR-022](docs/ADR-022-network-opt-in-as-peer-list.md).

### Image references

Steps resolve their execution image in one of three ways:

| Field        | Use case                     | Pinning                              |
|--------------|------------------------------|--------------------------------------|
| `image`      | External registry image      | Must contain `@sha256:` digest       |
| `image`      | Local bootstrap root         | Digest resolved via `podman inspect` |
| `image_from` | Output of a previous step    | Digest extracted at load time        |

`image_from` references an `oci-tar` output from an earlier step by name. The
executor loads the tar into the local container store and pins the image by its
manifest digest, creating an implicit DAG edge:

```yaml
  - name: stage_2
    image_from:
      step: build_image
      output: image
    args: [run, /src/bootstrap/lace.yaml]
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
cmd/strike/main.go               CLI entry point (run, validate, dag, compare)
internal/
  container/
    engine.go                     Engine interface, types, socket detection
    transport.go                  Unix socket and TCP HTTP transport
    podman.go                     Podman libpod REST API implementation
  lane/
    schema.cue                    CUE schema (source of truth)
    cue_types_lane_gen.go         Generated Go types (do not edit)
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
    sign.go                       ECDSA P-256 cosign-compatible signing
    sbom.go                       CycloneDX 1.6 SBOM generation
  registry/
    cache.go                      Spec hashing and cache tagging
    client.go                     Registry operations (Engine API, go-containerregistry)
  deploy/
    deploy.go                     Deploy with mandatory state attestation
bootstrap/Containerfile           Self-contained bootstrap image
lane.yaml                         Top-level bootstrap lane
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
