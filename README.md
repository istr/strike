# strike

Reproducible, rootless CI/CD lanes. No shell. No root. No local toolchain.

## What is strike?

strike is a cloud-native lane executor that treats containers as the only
unit of computation. Every step runs in a pinned, digest-verified OCI image
with network disabled by default. There is no shell interpreter, no script
block evaluation, no implicit host dependency beyond a working rootless
container runtime.

Lanes are declared in YAML, validated against a CUE schema, and executed as
a content-addressable DAG. Outputs are cached as OCI artifacts in any standard
registry.

## Prerequisites

You need exactly two things:

1. **Podman (rootless)** -- the only host binary strike depends on at runtime.
2. **A git-capable IDE** (e.g. VS Code, JetBrains) -- for cloning and editing
   the repository. You do not need a local `git` CLI; your IDE handles that.

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
podman run strike:stage_1
```

This executes the bootstrap lane (`lane.yaml`):

1. **keygen, build_binary, build_package, build_image** -- strike builds itself
   from source using pinned Chainguard tooling (go, melange, apko), producing
   the `strike:stage_2` image.
2. **stage_2** -- `strike:stage_2` rebuilds itself into `strike:stage_3` by
   running `bootstrap/lace.yaml`. The stage_2 image is resolved via
   `image_from`, pinned by the manifest digest extracted at runtime.
3. **compare** -- verifies that stage_2 and stage_3 produce identical images,
   proving the build is reproducible.
4. **publish** -- pushes the verified image to the registry.

## How it works

### Lane schema

Lanes are YAML files validated against an embedded CUE schema. Every
external container image must be SHA-256 pinned:

```yaml
steps:
  - name: build
    image: cgr.dev/chainguard/go@sha256:abc123...
    args: [build, -C, /src, -o, /out/binary, .]
    network: true
    sources:
      - path: .
        mount: /src
    outputs:
      - name: binary
        type: file
        path: /out/binary
```

Steps run with `--network=none` by default. Set `network: true` to allow
outbound access (e.g. for fetching dependencies or pushing to a registry).

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
- source file hashes

Cache lookup is local-first, then remote. Cache artifacts are stored as OCI
images in any standard registry.

### No shell

strike lanes do not use shell interpreters. Steps specify an image and an
args array. There are no `run:` blocks, no `bash -c`, no string interpolation.
Secrets are passed as environment variables, never written to process arguments.

## Project structure

```
main.go                 CLI entry point (run, validate, dag, compare)
executor/podman.go      Container execution via podman
lane/schema.cue         CUE schema (source of truth)
lane/parse.go           YAML parsing + CUE validation
lane/dag.go             DAG construction + topological sort
registry/cache.go       Spec hashing + cache tagging
registry/client.go      Registry operations (skopeo, podman)
bootstrap/Containerfile Self-contained bootstrap image
bootstrap/lace.yaml     Rebuild lane for reproducibility proof
lane.yaml               Top-level bootstrap lane
```

## License

See [LICENSE](LICENSE).
