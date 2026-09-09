# Development host premises

This is the operating procedure for the development environment that
[ADR-055](ADR-055-hardened-endpoint-development-premise.md) names as the
reference. The ADR is the record and the reasoning; this document is the
how. Where the two disagree, the ADR wins and this document is wrong.

## The endpoint

Development, gating, bootstrapping, and release happen on a hardened
endpoint on which exactly four capabilities exist:

1. a rootless container engine, reachable through its socket;
2. an IDE;
3. a git client;
4. an AI coding agent integrated into the IDE, running inside a container the
   engine starts.

Nothing else is installed or installable, and nothing the operator can write
is executable. This is the README's first sentence -- "no local toolchain" --
applied to the project's own development. A machine with more than these four
capabilities is a convenience, and nothing in the project may depend on the
convenience. When a step in this document works on such a machine and cannot
work on the endpoint, the document says so.

"Toolchain" means "image": the Go toolchain, the linters, the CUE tooling,
the agent's runtime, and strike itself exist only as digest-pinned images
reached through the engine.

## The dev container

The editor's user interface runs on the host. Its server, terminal, language
services, extensions, the agent, the toolchain, and git run inside a
container declared in `.devcontainer/` against the Dev Containers
specification. The working tree is bind-mounted into the container at its
host path; the host engine's socket is bind-mounted in and exposed as
`CONTAINER_HOST`; the container shares the host's network namespace. A
container started from inside it is a sibling on the host engine, and the
controller's loopback is the host's loopback -- both are load-bearing for
strike's mediator and resolver (ADR-028), not tuning.

Prerequisites on the host:

- The engine socket is served and named by `CONTAINER_HOST`. The dev
  container definition needs the socket's path without the scheme:

  ```sh
  export STRIKE_ENGINE_SOCKET="${CONTAINER_HOST#unix://}"
  ```

- The editor's Dev Containers implementation is pointed at the podman binary
  (in VS Code: the `dev.containers.dockerPath` setting set to `podman`).

Open the repository folder in the editor and reopen it in the container. The
editor builds the image through the engine (`podman build` is engine
functionality and is the only build path on the endpoint), starts the
container, and installs its own server and the agent extension into it.
Nothing executable lands on the host.

The container runs as `dev`, uid 1000, with the host user's identity mapped
onto it (`--userns=keep-id:uid=1000,gid=1000`), so files it writes in the
working tree belong to the host user.

### What the image contains

The image is built from `.devcontainer/Containerfile`: the Go toolchain of
the version `go.mod` demands, the C toolchain the race detector needs, `git`,
`make`, `golangci-lint`, `govulncheck`, and the agent. The base image and the
Go tools are pinned by digest and version.

The version in the tree at the time of writing is a measured first version
and does not yet conform to ADR-055 D3: its Node.js runtime comes from a
distribution repository and is past upstream end of life, and the agent
arrives through a Dev Containers feature at a floating version. The
Containerfile says so in its header. The conforming rework -- runtime copied
from a digest-pinned image, agent at a pinned version, no feature, a
`cgr.dev` base where one exists -- is owned by the roadmap. Until it lands,
do not read the current file as a precedent for either practice.

## Two gates, and where each runs

**The working-tree gate** runs inside the dev container over the
uncommitted, bind-mounted tree: after every code change and before
submitting. It is the gate `AGENTS.md#build-and-gates` names, run inside the
container rather than on the host. It is unattested and discretionary; its
job is the correctness of a change.

**The commit gate** is a strike lane over a pushed, content-addressed
revision, terminating in a registry deploy under the live keyless chain
(ADR-040). It is attested and structural: it blocks merge. The same lane file
runs from the dev container against the host engine and from a forge runner.
Its job is proof over a revision.

Neither substitutes for the other. A lane cannot see an uncommitted tree
(ADR-011); the working-tree gate cannot attest. A commit gate that fails
after a green working-tree gate is a round trip, not a defect on `main`.

## Build outputs never target the working tree

The working tree's bind mount inherits the host's `noexec`. A binary built
into it cannot be executed, not even inside the container. `go test`,
`go run`, `go generate`, and the `go tool` gates are unaffected: their
binaries live under the container's own temporary and cache directories.
`go build` is affected; build into a container-local path:

```sh
go build -o /tmp/strike ./cmd/strike
```

The bootstrap Containerfile is unaffected: it builds inside its own image
stage.

## Integration tests from the dev container

The hermetic suite (`STRIKE_INTEGRATION=0`) runs unchanged inside the
container. The integration suite runs against the host engine through the
mounted socket and against the sigstore harness on the host's loopback; host
networking makes both reachable.

Four tests in `test/integration` bind a `t.TempDir()` path into a step
container. `testing.T.TempDir` honors `GOTMPDIR`, and `GOTMPDIR` is also
where `go test` writes and executes the compiled test binary, so the
directory it names must be both exec-capable and visible to the host engine
at the same path.

- On a development machine whose home is exec-capable this is satisfied by
  one shared scratch directory bind-mounted into the container at its host
  path, without `noexec`, with `GOTMPDIR` pointing at it. The full suite is
  green with that configuration.
- On the hardened endpoint it cannot be satisfied: every host-visible path
  the operator can write is `noexec`, and every exec-capable path inside the
  container is invisible to the host engine. The four tests fail there until
  they are reshaped to bind no host path (item-0125, on which ADR-055 M7
  records the ratified resolution). Production strike binds no host path;
  only these tests do.

## Secrets

The dev container protects the host. It does not protect what lies inside
it: the agent can read anything mounted or injected into the container. No
long-lived secret is mounted into it -- not an SSH key, not a cloud
credential file. The OIDC token a registry deploy needs is minted for one
lane run, injected into that run's environment, and never persisted in the
container or the tree.

## Bootstrapping strike on the endpoint

`podman build` of `bootstrap/Containerfile` is the only path to a strike
binary on the endpoint, so that file is on the critical path of everything
downstream. At the time of writing it builds the tree it pins; the image's
default command still runs the root `lane.yaml`, which does not validate, so
the published `podman run` step of the ADR-009 proof is not yet runnable.
The [Beta Definition of Done](BETA-DEFINITION-OF-DONE.md) records this under
its 2026-09-05 amendment.
