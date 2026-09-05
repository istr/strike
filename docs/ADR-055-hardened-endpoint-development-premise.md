# ADR-055: The hardened endpoint is the development premise

## Status

Accepted, 2026-09-05. The measurement spike of 2026-09-05 at `f2b3c7e` and
its operator-authorized repair extension landing as `2fcbac9` and `c2f602c`
closed M1 (effect half), M2, M3, M4, M5, and the CLI half of M6; the results
are recorded in D7. The composition decision in D3 and the M7 resolution were
ratified on 2026-09-05. Two observations are not decisions and stay outside
this record's acceptance: the editor half of M6 is the operator's observation
on the reference endpoint, and the locking half of M1 is measured there and
nowhere else.

Sharpens the [Beta Definition of Done](BETA-DEFINITION-OF-DONE.md) (ratified
2026-07-02 at 3db7843) by naming the environment in which its gate matrix is
evaluated; the record's first dated amendment lands with this ADR. Gives the promise in the
first sentence of `README.md` its first in-tree definition. Consistent with
[ADR-009](ADR-009-bootstrap-reproducibility-proof.md) (the bootstrap chain),
[ADR-011](ADR-011-sources-elimination.md) (no host path enters the DAG),
[ADR-028](ADR-028-step-container-egress-mediation.md) (the mediator listens on
the controller's loopback and pasta forwards to it),
[ADR-035](ADR-035-build-payload-in-engine.md) (no host scratch),
[ADR-037](ADR-037-two-engine-trust-layers.md) (which engine identity a record
carries), and [ADR-046](ADR-046-one-canonical-digest-pinned-image.md) (one
digest-pinned image reference). Makes no schema change and touches no attest
wire; this is not a freeze event.

## Context

`README.md` opens with one sentence: "Reproducible, rootless CI/CD lanes. No
shell. No root. No local toolchain." Four of its five promises are principles in
`DESIGN-PRINCIPLES.md` and are gate-enforced. The fifth, "no local toolchain",
occurs exactly once in the tree -- in that sentence. It has no definition, it is
not a principle, and its only gate is Beta DoD row 10, which is red.

Two roadmap arcs are broken for the same reason, and the reason is that this
promise has no body. The `build-toolchain` arc assumes a Go toolchain on the
host: every item in it retires a Makefile target into a `go tool` or `go run`
invocation the operator types at a shell. The `beta-readiness` arc's gate item
(item-0063) assumes a hosted runner and at the same time claims to be "the
single check orchestration that replaces the aggregate `make check`" -- a claim
that item-0096 restates as its own acceptance. A strike lane structurally
cannot see an uncommitted working tree (ADR-011), so a lane can be a merge gate
and cannot be a pre-submit gate; "single" is false, and it is load-bearing:
followed literally, item-0096 deletes the executor's only pre-submit gate and
names as its replacement something that cannot occupy that position. Neither
arc states the environment it is planning for, so neither can notice that its
items contradict each other.

The environment that makes the README's sentence true is easy to state and
already exists as a class of workstation: a hardened endpoint on which the
operator can run a rootless container engine and an IDE, and nothing else. On
such a host nothing the operator can write is executable, nothing can be
installed system-wide or per user, and the only way to execute anything is to
start a container through the engine. `make` does not exist there. `go` does
not exist there. A `strike` binary in the home directory does not run there.
The README's promise is not a convenience for users on such hosts; it is the
only mode of operation they have.

strike is built in an AI-heavy workflow whose executor is a coding agent
integrated into the IDE. Those agents, as shipped, run on the host and use its
toolchain extensively. On the hardened endpoint there is no host toolchain to
use, so the executor either runs somewhere else or the premise is false. The
mechanism that resolves this exists and is documented by the vendors on both
sides: an editor implementing the Dev Containers specification keeps its user
interface on the host and runs its server, its terminal, its language services,
its extensions, and the coding agent inside a container that the engine starts,
with the working tree bind-mounted in. The agent then still uses "local"
tooling extensively -- but "local" is the container's filesystem, and the
container's contents are a declared, digest-pinned image. What was a problem
becomes the inventory.

## Decision

### D1 -- The hardened endpoint is the reference development environment

strike is developed, gated, bootstrapped, and released from an endpoint on
which exactly four capabilities exist:

1. a rootless container engine, reachable through its socket;
2. an IDE;
3. a git client, host-side through the IDE or inside the executor's container,
   or both;
4. an AI coding agent integrated into the IDE -- the capability that joins
   code and model on the endpoint -- running inside a container the engine
   starts.

Nothing else is installed. Nothing else can be installed, system-wide or per
user. Nothing the operator can write is executable. The endpoint has network
reach to every service a lane with a registry deploy needs; from D2 and from
capability 4 it follows that it also reaches the registries the toolchain
images come from and the agent's inference endpoint.

This is the README's first sentence applied to the project's own development.
strike is built under the same promise it makes to a user. Any environment with
more than these four capabilities is a convenience, and nothing in the project
may depend on the convenience.

### D2 -- "Toolchain" means "image"

Every tool the project depends on -- the Go toolchain, the linters, the CUE
tooling, cosign, the container that carries the executor, and strike itself --
exists only as a digest-pinned image reached through the engine. A build, test,
lint, release, or bootstrap step that requires an executable on the host is a
defect against this premise. It is not a convenience to be removed later.

`podman build` is engine functionality and is permitted. It is therefore the
only way strike is built on the reference endpoint, and `bootstrap/Containerfile`
is the only path to a strike binary. That file moves from release mechanics to
the critical path of everything downstream.

### D3 -- The executor runs in a dev container, and the container protects the host

The executor's container is declared in the repository under `.devcontainer/`,
against the Dev Containers specification, with a `Containerfile` whose base
image and every installed tool are digest-pinned. The editor on the host
connects to it; the editor's server, terminal, extensions, the agent, the
toolchain, and git run inside it. The working tree is bind-mounted into the
container at its host path. The host engine's socket is bind-mounted into the
container and exposed as `CONTAINER_HOST`, and the container shares the host's
network namespace, so a container started from inside the executor's container
is a **sibling** on the host engine and the controller's loopback is the
host's loopback (M2, M3 below). The container runs as a non-root user with the
host user's identity mapped in.

Everything in the image arrives through the `Containerfile`. The Dev
Containers *features* mechanism is not used: a feature is a shell installer
that adds package repositories and pulls by tag at build time, which is
unpinned by construction and contradicts D2 (M6 below). The agent is installed
from a version-pinned package, and the runtime it needs is copied from a
digest-pinned image rather than installed from a distribution repository. No
runtime in the image is past its upstream end of life.

Base images the project builds from -- the dev container, the bootstrap
stages, and any image the project authors for itself -- come from `cgr.dev`
(Chainguard) where an image exists there, matching the images the lanes
already reference. "Where an image exists" is established by measurement in
the change that adopts it (the Go minor `go.mod` demands, the C toolchain
`-race` needs, a supported Node.js line), never assumed.

The `.devcontainer/` at `c2f602c` is a measured first version and does not
conform to this decision: its runtime comes from a distribution repository
and is past end of life, and its agent arrives through a feature at a
floating version (M6). It is retained as the working baseline the rework
starts from, carries a comment naming this ADR and the non-conformance until
the rework lands, and is not a precedent. The decision above is not relaxed
to match it.

The container's security goal is stated narrowly and deliberately: **it
protects the host, not what lies inside it.** The agent may modify any file in
the bind-mounted working tree and reach anything the container's network
policy allows; anything mounted or injected into the container -- the agent's
own credentials, an OIDC token for a deploy, registry credentials -- is
exposed to whatever runs there. Long-lived secrets are therefore never mounted
into it. Tokens are short-lived and scoped to one lane run. This is the
vendor's own stated boundary for the mechanism, and the project adopts it as
the design target rather than as a caveat.

The dev container is not a step container and is not on the execution path.
It deliberately carries what a step container must not: a shell, a toolchain,
a git client, an agent. The boundary between it and the attested path is the
engine socket: what crosses that socket is a lane run or a direct engine
invocation, and the attested path begins on the far side of it.

### D4 -- There are two gates, distinct by construction

A **working-tree gate** runs inside the executor's container, over the
bind-mounted, uncommitted tree, per edit and before submission. It is a
sequence of toolchain invocations. It is unattested, discretionary, and fast.
Its job is the correctness of a change.

A **commit gate** is a strike lane run over a pushed, content-addressed
revision, terminating in a registry deploy under the live keyless chain. It is
attested, structural (it blocks merge), and slow. Its job is proof over a
revision. The same lane file runs from the workstation's dev container against
the host engine and from a forge runner; only the place it is started from
differs.

Neither substitutes for the other. The working-tree gate cannot attest; the
commit gate cannot see an uncommitted tree. The phrase "single check
orchestration" is struck from item-0063 and item-0096, and no future item may
require one artifact to serve both inputs. A commit gate that fails after a
green working-tree gate is a round trip, not a defect on `main`; that is the
division of labour that makes the working-tree gate's discretionary character
acceptable.

### D5 -- strike runs as a container process; host paths bind in exactly one place

On the reference endpoint strike executes as a container process, either inside
the executor's container against the mounted host socket (the daily path) or as
the bootstrap `stage_1` image with its own nested engine (the reproducibility
proof of ADR-009). The operator's engine invocation -- the dev container
definition, or the `podman run` line the README publishes -- is the single
entry point of the workflow and the only place where a host path is bound.
strike itself binds none (ADR-011, ADR-035).

The two topologies are not interchangeable and the choice is visible in the
record: in the sibling topology the engine identity a deploy record carries is
the host engine's; in the nested topology it is the inner engine's (ADR-037).
The nested topology is reserved for the bootstrap proof.

### D6 -- Beta means: the gate matrix is green in this environment

The Beta Definition of Done is sharpened, not replaced. Every row of its gate
matrix is evaluated on the reference endpoint. A gate whose check requires an
executable on the host is red by definition, whatever it reports elsewhere.
Row 10 ("no local toolchain") stops being one promise among fourteen and
becomes the environment in which the other thirteen are judged.

### D7 -- Measured points, and what stays open

Each of the following depended on the behaviour of the engine, the kernel, or
the editor rather than on reading the design. A ratified guess in an
append-only document costs an amendment to correct, so each was measured by a
throwaway spike on 2026-09-05 against anchor
`f2b3c7e404e273feeaaf2121a1747d893e4253d8`, on a development machine that
still carries a host toolchain, with the `noexec` property of the hardened
endpoint simulated by a `noexec` bind mount. The candidate image was
`docker.io/library/golang:1.26.8` at
`sha256:2d54f6c8c6ea532a321e0b4c69553b2ed3637608d4f4357dbed37939fe2620cc`
with golangci-lint 2.13.2 and govulncheck 1.7.0. A repair extension of the
spike, authorized by the operator, then landed `bootstrap/Containerfile`
(`2fcbac9`) and `.devcontainer/` (`c2f602c`) and re-measured against them.
Results:

- **M1 -- `noexec` propagation into the bind-mounted working tree.**
  *Measured, effect half.* The workspace bind mount carries `noexec` inside
  the container; `go build -o` into the workspace produces a binary the
  runtime refuses to execute (`permission denied`, exit 126); the same build
  into the container's own `/tmp` runs. `go test`, `go run`, `go generate`,
  and the `go tool` gates are unaffected because their binaries live under
  the container's own temporary and cache directories. Consequence: every
  build output on the reference endpoint targets a container-local path,
  never the workspace. *Open, endpoint-only:* whether a rootless user
  namespace can clear the flag on the hardened endpoint (expected: no, the
  flag is locked); this is measured on the endpoint itself, not here.
- **M2 -- The sibling topology's network path.** *Measured.* With
  `--network=host` the full test suite -- lane runs through `cmd/strike`, the
  keyless deploy path, the mediator and the DoT dialer -- passes from inside
  the container against the host engine and the host-loopback harness.
  Without it, the same controller cannot reach host-loopback services at
  all: the harness readiness probe blocks until the test timeout. Host
  networking is required and, with the socket mount, sufficient. Side
  finding: the readiness probe in the test harness helper has no timeout of
  its own and fails as a silent hang rather than an error; that is a
  test-hygiene defect with its own follow-up. See M7 for the one part of the
  suite that host networking does not carry.
- **M3 -- Engine socket reachability from inside.** *Measured.* The socket
  bind-mounts, the mapped user opens it, `Ping`, `Info` and the version gate
  pass, and containers started through it run on the host engine as
  siblings.
- **M4 -- The working-tree gate runs green inside the image.** *Measured,
  with one image-construction defect.* `go generate ./contract`, the
  golangci-lint gate, the three `go tool` gates, the CUE format check,
  govulncheck, the hermetic suite under `-race`, and the static build all
  pass from a fresh clone; the image carries the C toolchain `-race` needs.
  The one failure was the architecture-lint gate, and it was not a code
  finding: it is invoked as `go run <module>@<version>` outside the module
  graph, which must write to the checksum-database cache, and the spike
  image had created that cache root-owned during its own build. The landed
  image (`c2f602c`) gives `/go` to the non-root user and pins the two
  installed tools to the versions the spike observed; the gate then passes
  (`OK - No warnings found`). The structural consequence stands beside the
  fix: the architecture linter is rehomed as a `tool` directive in `go.mod`
  so it is verified against `go.sum` like every other tool and touches no
  checksum database at run time. Weakening checksum verification to make
  the ad-hoc invocation pass is rejected.
- **M5 -- The bootstrap Containerfile at the anchor.** *Measured.* The build
  fails at its CUE codegen step before reaching the layout drift the static
  reading predicted: the distribution `cue-cli` (0.15.3) rejects the module's
  declared language version (0.16.0). The first defect is the unpinned
  distribution CUE binary -- the exact defect ADR-050 removed from the
  Makefile and the Containerfile never received. Item-0062's blocking finding
  is confirmed dynamically, with its first failure one step earlier than
  predicted. The repair (`2fcbac9`) found two further defects stacked behind
  the first: the `golang:1.26-alpine` base carried Go 1.26.1 under
  `GOTOOLCHAIN=local` and could not satisfy the module's `go 1.26.8`, and a
  bare `go get` at a module root without Go files fails on this toolchain.
  The landed file pins `golang:1.26.8-alpine` by digest, runs
  `go mod download` and `go generate ./contract`, and installs no CUE binary;
  `podman build` at the anchor completes both stages. What M5 does not
  close: the image's `CMD ["run"]` still executes the root `lane.yaml`, which
  does not validate, so the published `podman run` step and Beta DoD row 11
  remain red until the bootstrap lane has an owner.
- **M6 -- The editor half of the mechanism.** *CLI half measured; editor half
  operator-observed at landing.* The
  reference Dev Containers CLI consumed the repository's `devcontainer.json`,
  resolved its variables and its `remoteUser`, and reached the image build.
  The build then failed inside the vendor's agent *feature*: its installer
  added an end-of-life upstream package repository, installed the
  distribution's own Node.js without its package manager, and aborted. The
  vendor documents a workaround (a second feature ahead of the first). This
  ADR draws the other conclusion: the failure exposed that a feature is a
  shell installer over unpinned repositories. The repair extension took the
  vendor's route instead (`c2f602c`): Node.js and npm from the base image's
  distribution repository, the agent feature kept and pinned by digest
  through the CLI's lockfile. Against that image the CLI half is *measured*:
  `up` succeeds, the mapped user, the socket, `CONTAINER_HOST`, the
  workspace mount and `claude --version` all arrive inside. Two facts about
  the composition are recorded for the D3 ratification rather than settled
  here: the distribution runtime is Node.js 20, past upstream end of life
  since 2026-04-30 and below the agent package's declared `>=22`; and the
  feature installs the agent unpinned, so its version changes on rebuild
  without a commit. Ratified 2026-09-05: D3 names the Containerfile-only
  composition; the landed version is marked non-conformant and reworked. The
  editor half proper -- server installation, extension panel, credential
  forwarding, sign-in callback -- is operator-observed at landing.
- **M7 -- Test-side host round trips under the sibling topology.** *Found,
  not resolved.* Four tests in `test/integration` bind a `t.TempDir()` path
  into a step container; from inside the dev container the host engine
  cannot see that path and every one of them fails with `statfs ...: no such
  file or directory`. Production binds no host path -- a capture mount's
  source is an engine mount source by contract, and no agent socket is
  mounted -- so this surface is exactly the test-side exemption item-0125
  already targets. The spike's own attempt to redirect those paths was
  self-defeating: `testing.T.TempDir` honors `GOTMPDIR`, and the spike set
  `GOTMPDIR` to the container-local `/tmp` while pointing `TMPDIR` at the
  host-identical mount. The repair extension found the real constraint:
  `GOTMPDIR` is both where `go test` writes and executes the compiled test
  binary and where `t.TempDir()` output lives, so the mount it names must be
  exec-capable and host-visible at once. On the development machine that is
  satisfied by a shared scratch mount without `noexec`, and the full suite
  is green from the dev container with it. On the hardened endpoint it
  cannot be satisfied at all: every host-visible path the operator can write
  is `noexec` (D1, M1), and every exec-capable path inside the container is
  overlay-backed and invisible to the host engine. The environment redirect
  is therefore a development-machine convenience, not a premise-conformant
  configuration. Ratified 2026-09-05: the four tests are reshaped to bind no
  host path -- the resolution consistent with ADR-035 and D5 -- and
  item-0125 precedes the commit-gate items in the roadmap revision.

## Consequences

- `.devcontainer/` is a first-class, digest-pinned artifact. Its
  `Containerfile` is subject to the same pinning discipline as a lane image
  reference; whether the existing gates cover Containerfile pins is a
  question for the roadmap revision. The version at `c2f602c` is reworked to
  D3 -- no feature, runtime from a digest-pinned image, agent at a pinned
  version, `cgr.dev` base where available -- by an item the roadmap revision
  creates; until that lands, the file carries a comment naming this ADR and
  the non-conformance (D3, M6).
- Build outputs on the reference endpoint never target the workspace (M1).
  The documented build command writes to a container-local path, and the
  bootstrap Containerfile builds inside its own stage, unaffected.
- The dev container runs with host networking and the mounted engine socket
  (M2, M3); both are declared in `.devcontainer/` and documented as
  load-bearing, not as tuning.
- The architecture linter joins `go.mod` as a `tool` directive and the
  ad-hoc `go run <module>@<version>` form is retired (M4). This rides
  item-0096's rehome and closes its rehome list for that gate.
- The four host-round-trip tests in `test/integration` are on item-0125's
  surface. From the dev container they pass only with an exec-capable,
  host-visible scratch mount, which the hardened endpoint cannot provide
  (M7); on the reference endpoint they fail until reshaped. item-0125 moves
  ahead of the commit-gate items in the roadmap revision on that ground.
- The bootstrap Containerfile's builder stage is on `docker.io`; D3's
  `cgr.dev` rule reaches it through item-0062, subject to the same
  availability measurement.
- The harness readiness probe's missing timeout (M2 side finding) becomes a
  proposed test-hygiene item.
- `docs/DEVELOPMENT-HOST-PREMISES.md`, landing with this ADR, carries the
  operating procedure: bringing the dev container up, what the image
  contains, the socket mount, credential handling, and the two gates.
  `AGENTS.md` rewrites its gate section against the dev container when
  item-0096 retires the Makefile: "the verbatim gate" becomes the documented
  working-tree sequence, run inside the container.
- The root `Makefile` is dead on the reference endpoint by environment, not
  by decision. item-0096 keeps its documentation migration and its rehome of
  the thin wrappers; its dependency on item-0063 is re-derived, because the
  lane was never the working-tree gate's replacement.
- item-0063 is a commit gate. Its "single check orchestration" clause is
  struck. The working-tree gate has a named home -- the dev container -- so
  item-0016 and any future gate item name which of the two gates hosts it.
- `bootstrap/Containerfile` is on the critical path of everything: item-0062
  precedes item-0063, and the dynamic confirmation in M5 replaces the static
  finding item-0062 currently carries. Its repair follows ADR-050: no
  distribution CUE binary, codegen through `go generate ./contract`.
- The Beta Definition of Done receives its first dated amendment in the
  same change: row 10 becomes the evaluation environment (D6); row 11 moves
  from `pending` to `red`, because the root `lane.yaml` at the anchor does
  not validate and the compare step has not been runnable since ADR-039 D5;
  row 12 no longer reads "verbatim `make check`"; the gate-eligibility
  clause, which names `make check` as one of four categories, is restated
  against D4; and the record's own drift since ratification -- a resolved
  ratification point, a retired deferral, and the attest wire changes that
  landed under ADR-051 after the freeze took effect -- is written down where
  it can be diffed.
- Secrets that reach the dev container are short-lived by policy (D3). The
  OIDC token for a deploy is minted for one lane run and injected into the
  environment of that run, never persisted in the container or the tree.
- The two roadmap arcs are re-derived against this ADR in a single revision
  scheduled behind its landing. That revision owes answers the ADR does not
  give: where the ADR-009 bootstrap lane lives once the root `lane.yaml` is
  repurposed, and which item owns the `stage_2`/`stage_3`/compare chain and
  the missing `bootstrap/lace.yaml`; whether item-0063 gains explicit
  infrastructure dependencies (runner, resolver, registry, hosted keyless
  chain, OIDC token, branch protection) with owner items or records them as
  operator-provided; whether the forge runner builds strike from source or
  consumes a released image; and the widening of item-0096's acceptance to
  the full set of files carrying make-target references, including three
  ADR bodies under the append-only policy.
- "No local toolchain" becomes a candidate for promotion to a principle in
  `DESIGN-PRINCIPLES.md` once further decisions embody it. Promotion is not
  performed here; the principles document is over its read-fully limit and the
  governance model promotes on crystallization, not on declaration.

## Alternatives considered

- **Executor on the host, as the agents ship.** Rejected: on the reference
  endpoint there is nothing on the host for it to use, and the premise would
  be false at the first `go build`. This is the de facto arrangement the two
  broken arcs were silently planning for.
- **Remote executor (a cloud dev environment or a remote VM over SSH).**
  Permitted -- the Dev Containers mechanism runs there unchanged -- but not the
  reference. The premise is a local endpoint, and a remote host reintroduces
  exactly the trust-domain question ADR-037 exists to bound.
- **The bootstrap `stage_1` image as the daily vehicle** (nested engine,
  tmpfs storage). Rejected for daily use: every image is pulled twice, the
  storage is discarded with the container, and the engine identity in every
  record is the inner engine's rather than the host's. Retained for the
  ADR-009 proof, where the nesting is the point.
- **One gate for both inputs, by running the lane over a loopback git server
  refreshed on every edit.** Rejected as the per-edit gate: a push per
  iteration, a live keyless chain, and a registry deploy for every lint fix,
  against a gate contract that runs after every code change. The two-gate
  split (D4) is the honest shape.
- **Keep the landed dev-container composition** (distribution Node.js, the
  agent through a lockfile-pinned feature). Considered because it works and
  is measured. Rejected: the runtime is past upstream end of life and below
  the agent's declared floor, the agent's version floats on rebuild without
  a commit, and a feature is a shell installer over repositories the
  project does not pin. A measured first version is the right starting
  point for the rework and the wrong thing to ratify.
- **Relax the premise: allow a Go toolchain on the host for development.**
  Rejected: it is the README's first sentence. A project that ships "no local
  toolchain" and needs one to build itself has not redeemed the promise; it
  has excused itself from it.

## Principles

- **Restricted by default, relaxed only with reason.** The reference
  environment is the most restricted one that can run the project at all;
  every additional capability is a convenience nothing may depend on.
- **External references are digest-pinned.** The executor's own toolchain is
  an image reference under the same discipline as a lane's, so the
  development environment cannot drift any more than a step can.
- **Reproducibility is enforced, not hoped for.** The same dev container image
  and the same lane file run on the workstation and on the forge runner; the
  environment is part of what is reproduced.
- **No shell.** The principle keeps its scope, the execution path; this ADR
  draws the line that keeps the executor's container, which has a shell, off
  it.
- **No exec.** The principle keeps its scope, the controller process; the
  executor's container spawns processes and is not the controller, and the
  module-wide `os/exec` ban is not relaxed for it.
- **Enforcement is structural, not discretionary.** A gate that needs a host
  executable is red on the reference endpoint whether or not anyone runs it
  there; the environment enforces the promise the README makes.
- **Code is liability.** The premise adds no host tooling, no in-tree gate
  runner, and no exemption to the module-wide `os/exec` ban; it moves the
  toolchain into an image the project already knows how to pin.

## Amendment 2026-09-05 -- the M2 side finding overstated the probe's defect

M2 records as a side finding that "the readiness probe in the test harness
helper has no timeout of its own and fails as a silent hang rather than an
error". Read against the tree, the first half is wrong.
`internal/testutil/harnessrecover.go` is unchanged since `a7682a6`
(2026-09-01), before the spike's anchor `f2b3c7e`; its blob at both anchors
is `3e00d6c`. The readiness phase is bounded by `readyBudget` (180 seconds)
as one shared context deadline, each request by `probeTimeout` (10
seconds), and the pause between attempts by `pollInterval` (2 seconds), all
as scoped contexts, so a cancelled parent ends the loop on its next check.
The probe cannot hang unbounded; it fails after its budget with an error
naming the endpoint and the last attempt's cause.

What stands is the second half, restated. The probe does not distinguish a
non-transient failure -- connection refused, no route, name resolution --
from a service that is not yet ready, and retries the former for the whole
budget; and the budget is per call, so several `RequireHarness` callers in
one package spend it in sequence. Under M2's wrong topology, no host
networking, that is minutes of deterministic failure before the first error
line, which reads as a hang from outside. Whether that is what the spike
observed is the operator's to confirm. The follow-up the Consequences
promise is item-0152, whose shape is this restatement and which is ratified
only against that confirmation.

**Supersedes, in D7 M2 above:** "has no timeout of its own and fails as a
silent hang rather than an error" is read as: "retries a non-transient
failure for its full per-call budget, which is a test-hygiene defect with
its own follow-up".

## Amendment 2026-09-05 -- the roadmap revision landed

The revision the Consequences schedule behind this ADR landed at `7c21e8e`,
the commit after this record. The answers it owed live in the item store
and are pointed at, not restated. The ADR-009 bootstrap lane has an owner,
item-0150, which also decides where the lane lives once the root
`lane.yaml` is not the only lane the stage_1 image can run. item-0063
records its infrastructure as operator-provided, consumes strike as a
released digest-pinned image rather than a binary built from the tree it
gates, and runs the hermetic suite because a step container reaches no
engine. item-0096 widens its acceptance to every file carrying a
make-target reference, the append-only ones amended rather than edited, and
precedes item-0063 rather than depending on it. item-0125 precedes the
commit-gate items. The dev container's D3 rework and the Containerfile pin
gate are item-0151. The freeze re-declaration and the ratchet's home are
recorded in the Beta Definition of Done's amendment of the same date.
