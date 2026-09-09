# Development endpoint premises

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

## Where the endpoint lives

The endpoint is a Linux environment (ADR-055 D8). On a Linux workstation it
is the workstation. Where the workstation runs macOS or Windows, it is a
local guest whose lifecycle the operator owns, and the workstation
contributes exactly two things: a hypervisor and the editor's user
interface.

| Workstation | Endpoint                                  |
| ----------- | ----------------------------------------- |
| Linux       | the workstation                           |
| macOS       | a Linux guest on Virtualization.framework |
| Windows     | a Linux guest on Hyper-V                  |

The working tree lives on the endpoint's own filesystem and arrives there
by git, never through a shared workstation directory. This is not a
preference. On Windows the workstation's path grammar is not a valid
container path, so the tree cannot be bound at its own path; and the
`noexec` property and the integration-test constraint below are properties
of the endpoint's own mount options, which a shared directory does not
carry. Sharing a workstation directory into the endpoint breaks all three
at once, and it is the layer the engine's own file-sharing defects live in.

Where the workstation does not run Linux, the editor connects to the
endpoint first and opens the working tree there; the dev container is then
started on the endpoint exactly as on a Linux workstation. Nothing below
varies by workstation operating system.

Two cautions. A guest that a container tool creates and recreates for its
own purposes is not a place to keep a working tree -- own the guest. And on
Windows, Hyper-V and WSL container machines cannot run at the same time.

## The dev container

The editor's user interface runs on the workstation. Its server, terminal,
language services, extensions, the agent, the toolchain, and git run inside
a container declared in `.devcontainer/` against the Dev Containers
specification, started on the endpoint. The working tree is bind-mounted
into the container at its endpoint path; the endpoint engine's socket is
bind-mounted in and exposed as `CONTAINER_HOST`; the container shares the
endpoint's network namespace. A container started from inside it is a
sibling on the endpoint engine, and the controller's loopback is the
endpoint's loopback -- both are load-bearing for strike's mediator and
resolver (ADR-028), not tuning.

Prerequisites on the endpoint:

- The rootless engine serves its socket at `$XDG_RUNTIME_DIR/podman.sock`,
  from a long-running user process the session starts:

  ```sh
  podman system service --time=0 unix://$XDG_RUNTIME_DIR/podman.sock
  ```

  systemd is neither required nor wanted. It is not one of the four
  capabilities, the reference endpoint does not run it, and nothing in this
  document depends on an init system: the socket is a process, not a unit.
  podman's own socket unit would serve `$XDG_RUNTIME_DIR/podman/podman.sock`
  instead; that path is not the premise, and the two are not
  interchangeable.

  The dev container definition names the socket through
  `${localEnv:XDG_RUNTIME_DIR}`, which every login session sets, and it
  carries no project-specific variable. An unset variable expands to the
  empty string, and the engine then rejects the whole invocation with
  `host directory cannot be empty`, which names neither the variable nor
  the mount it came from.

- The editor's Dev Containers implementation is pointed at the podman binary
  (in VS Code: the `dev.containers.dockerPath` setting set to `podman`).

Where the endpoint is a guest, connect the editor to it first. Then open
the repository folder and reopen it in the container. The editor builds the
image through the engine (`podman build` is engine functionality and is the
only build path on the endpoint), starts the container, and installs its
own server and the agent extension into it. Nothing executable lands on the
workstation, and nothing but the editor protocol crosses the hypervisor
boundary.

The container runs as `dev`, uid 1000, with the endpoint user's identity
mapped onto it (`--userns=keep-id:uid=1000,gid=1000`), so files it writes in
the working tree belong to the endpoint user.

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
container rather than on the endpoint. It is unattested and discretionary;
its job is the correctness of a change.

**The commit gate** is a strike lane over a pushed, content-addressed
revision, terminating in a registry deploy under the live keyless chain
(ADR-040). It is attested and structural: it blocks merge. The same lane file
runs from the dev container against the endpoint engine and from a forge
runner. Its job is proof over a revision.

Neither substitutes for the other. A lane cannot see an uncommitted tree
(ADR-011); the working-tree gate cannot attest. A commit gate that fails
after a green working-tree gate is a round trip, not a defect on `main`.

## Build outputs never target the working tree

The working tree's bind mount inherits the endpoint's `noexec`. A binary
built into it cannot be executed, not even inside the container. `go test`,
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
container. The integration suite runs against the endpoint engine through
the mounted socket and against the sigstore harness on the endpoint's
loopback; host networking makes both reachable.

Four tests in `test/integration` bind a `t.TempDir()` path into a step
container. `testing.T.TempDir` honors `GOTMPDIR`, and `GOTMPDIR` is also
where `go test` writes and executes the compiled test binary, so the
directory it names must be both exec-capable and visible to the endpoint
engine at the same path.

- On a development machine whose home is exec-capable this is satisfied by
  one shared scratch directory bind-mounted into the container at its
  endpoint path, without `noexec`, with `GOTMPDIR` pointing at it. The full
  suite is green with that configuration.
- On the hardened endpoint it cannot be satisfied: every endpoint-visible
  path the operator can write is `noexec`, and every exec-capable path
  inside the container is invisible to the endpoint engine. The four tests
  fail there until they are reshaped to bind no host path (item-0125, on
  which ADR-055 M7 records the ratified resolution). Production strike binds
  no host path; only these tests do.

## Secrets

The dev container protects the endpoint. It does not protect what lies
inside it: the agent can read anything mounted or injected into the
container. No long-lived secret is mounted into it -- not an SSH key, not a
cloud credential file. The OIDC token a registry deploy needs is minted for
one lane run, injected into that run's environment, and never persisted in
the container or the tree.

## Bootstrapping strike on the endpoint

`podman build` of `bootstrap/Containerfile` is the only path to a strike
binary on the endpoint, so that file is on the critical path of everything
downstream. At the time of writing it builds the tree it pins; the image's
default command still runs the root `lane.yaml`, which does not validate, so
the published `podman run` step of the ADR-009 proof is not yet runnable.
The [Beta Definition of Done](BETA-DEFINITION-OF-DONE.md) records this under
its 2026-09-05 amendment.
