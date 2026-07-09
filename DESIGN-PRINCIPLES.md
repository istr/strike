# Design Principles

strike is a rootless, shell-free, container-native CI/CD executor. Its
architecture is derived from a small set of principles chosen to support
two goals simultaneously: **software attestation and provenance tracing** --
end-to-end when the container engine shares the controller's trust domain
(local rootless, or remote with an attested TCB), best-effort and scope-marked
when it does not (see
[SECURITY.md](SECURITY.md#attestation-soundness-best-effort-vs-end-to-end)) --
and **systematic reduction of the supply-chain attack surface**.

These principles are the axioms of the project: schemas, APIs, and
implementation details evolve, but the principles are the invariant. The
project is in pre-beta -- breaking changes at the schema and implementation
layer are expected and deliberate; principle-level drift is not. When a feature
or abstraction is proposed, the question is not whether it is useful but whether
it is compatible with the principles.

Principles are not designed up front; they crystallize. A pattern noticed
across several decisions is recognized as invariant and captured here; the set
is strictly curated. This document *defines* the principles, it does not
enumerate which ADRs concretize them -- that mapping lives in each ADR's
`## Principles` section, aggregated in `docs/ADR-INDEX.md`, so the relation runs
one way (ADR to principle) and the documentation forms no cycle.

strike is built in an AI-heavy workflow: an operator working with
general-purpose language models makes architectural decisions, and coding
agents implement against these principles. "Code is liability" is positioned
first deliberately -- it is the principle most likely to be violated by
AI-generated contributions, and the other principles assume it.


## Code is liability

Every line of strike is attack surface, maintenance cost, and a
candidate failure mode. The project rejects abstraction for its own
sake, rejects dependencies that duplicate standard-library
functionality, and prefers a small targeted change to a framework
hook. "A little copying is better than a little dependency."

General-purpose language models exhibit a documented bias toward producing
more code rather than less -- a helper instead of an inline, a layer instead of
a direct call, a framework instead of a function. In a security tool that bias
is a supply-chain concern, not a style preference: code that does not exist
cannot be exploited, cannot regress, and cannot be the site of a future CVE.

The operational form of this principle:

- A change that removes more code than it adds is the default
  preferred shape of a contribution.
- A change that adds code must justify the additions against the
  alternatives that would not have added them.
- A new abstraction (interface, helper, package, dependency) must
  cite at least two existing call sites that benefit, not one
  hypothesis about future calls.
- A new dependency must replace more lines than it adds, including
  its transitive surface.


## No shell

Generic-purpose shells are prohibited anywhere in the execution path --
not in steps, not in build images, not in the runtime environment strike
provides. Shells structurally enable escaping, string-concatenation
attacks, and lateral movement. Step definitions specify an image and an
args array; there is no `run:` block, no `bash -c`, no string
interpolation. Using containers with a shell is an anti-pattern.


## No exec

strike's controller process does not spawn subprocesses. There are zero
`os/exec` imports in the codebase. All external work -- container
execution, state capture, probes, deploys -- happens inside containers
reached through the container engine REST API. This eliminates an entire
class of command-injection and path-hijacking vulnerabilities by design.


## No root

strike runs end-to-end under a rootless container runtime. There is no
privileged helper, no setuid binary, no daemon. Every step container
additionally drops all Linux capabilities, mounts its root filesystem
read-only, disallows privilege escalation, and runs with the network
disabled unless explicitly declared.


## Declarative type enforcement (CUE first)

All internal data contracts are formally expressed in CUE. Go types are
generated from CUE, not hand-written. YAML inputs and JSON outputs are
validated against the same schemas that generate the types. Schema drift
between definition and implementation is therefore structurally
impossible. This also provides the foundation for a dual-language
verification approach: a secondary implementation in a different
language can consume the exported schemas and verify strike's outputs
independently.


## Meaning is single-sourced

Every fact has exactly one authoritative definition, and everything else refers
to it. A constraint is expressed once -- as one CUE definition, one rule-table
row, one principle -- and never restated in a second place that can drift from
the first. When the same meaning is written twice, the copies diverge silently:
a schema says one thing and its prose comment says another, a rationale string
outlives the rule it explained, a doc asserts a property the code stopped
guaranteeing. Single-sourcing makes that class of drift structurally impossible rather than a
matter of diligence. It applies to the trust-layer derivation (the layer is
computed from provenance by one rule table, not asserted per field), to the
schemas (one CUE definition, types generated from it), and to the project's own
planning state (one roadmap item store, not a chat transcript). Its cost -- a
reference instead of a convenient restatement -- is the price of never having
two sources of truth disagree.


## Secrets are typed

Secret values are carried in a dedicated type whose every string,
format, and JSON serialization returns a redacted placeholder. They live
only in process memory, are passed to step containers via the engine
API request body, and never appear in strike's own environment, in
process arguments, in logs, or on disk. Leakage prevention is a
property of the type, not a discipline of the caller.


## Runtime is attested

Every step records not only its output artifact but the runtime context
that produced it: the container engine identity and transport
fingerprint, the resolved digests of all upstream inputs, pre- and
post-action state snapshots for deploy steps, and the full DAG
predecessor chain. Attestations are signed as DSSE envelopes and
submitted to a transparency log. The resulting chain is designed to be
verifiable without contacting strike or the original engine.


## Peers are declared

Network interaction is a typed trust contract, not a boolean. Any step
that uses the network must enumerate its peers together with the
appropriate trust anchor for each peer type: certificate fingerprint or
CA bundle for HTTPS, known_hosts entries for SSH, image digest for OCI
registries, explicit system-CA opt-in for public web. The declaration
bounds both the outbound egress surface and the set of accepted
upstream identities, and it becomes part of the step's attestation.
Binary `network: true` is not a valid expression.


## Identity is asymmetric

Client identity (the credentials a step uses to authenticate itself)
and server identity (the peers a step decides to trust) are attested
independently and carried by different mechanisms. Credential-holding
authorities such as ssh-agent, KMS, or OIDC workload identity delegate
signing power without revealing key material. strike mediates but does
not own the keys. Bundling the two identities into a single trust
configuration would produce a false-consolidated anchor that no
underlying protocol actually supports.


## External references are digest-pinned

Every external OCI image, git commit, or upstream file is referenced by
content address. `image:latest` is a parse error, not a
silently-resolved convenience. Mutable references are rejected before
the DAG is built, because a build whose inputs can drift after
validation cannot be reproducibly attested.


## Reproducibility is enforced, not hoped for

Output artifacts must be byte-identical for byte-identical inputs.
Timestamps follow `SOURCE_DATE_EPOCH`, file enumeration is canonicalized, layer
ordering is stable, and the lane's execution order is the lexicographically
smallest valid topological order of the step graph -- Kahn's algorithm with
byte-wise string comparison (Go `sort.Strings`, equivalent to Rust's default
`Ord` on `&str`) -- so the same graph yields the same `dag.Order` across runs,
machines, languages, and implementations. All time access is dispatched through
`internal/clock`: `clock.Reproducible()` for values that end up in artifact
content bytes, `clock.Wall()` for event receipts and telemetry. Direct imports
of the standard-library `time` package are rejected in CI outside that one file.
Without this property, the cross-implementation verification that the CUE-first
principle exists to support cannot distinguish correctness from coincidence.


## Containers are the only storage

Strike does not implement a cache, a state directory, or a host-side
intermediate filesystem. Every artifact that survives a step boundary is an
OCI container image. The container engine's local image store is the storage
and cache layer; an OCI registry provides optional cross-machine and
long-term persistence. Strike's storage interface is the container engine
API; registry interaction is an explicit operation, not the default storage
path.


## Restricted by default, relaxed only with reason

strike's default posture for every capability is the most restricted one
that still functions: no network egress, TLS 1.3, all capabilities
dropped, read-only root filesystem, mutable references rejected. A
capability is widened only when a concrete need requires it, and every
widening is explicit, scoped to the narrowest surface that satisfies the
need, justified by a named reason, and -- where the reason has a horizon
-- given an expiry.

The pattern recurs throughout the architecture:

- Network egress is denied by default: a step reaches the network only by
  enumerating peers, and a peer-less step runs under an empty-allowlist capsule.
  The capsule still exists rather than falling back to a bare `--network=none`,
  so a denied attempt is an observable, attested refusal, not an opaque kernel
  drop.
- TLS is pinned to 1.3 on every controller-side connection (engine mTLS, the
  DoT resolver); the floor drops to 1.2 only on the external-peer dial, because
  real registries cap there. The relaxation is bounded (version floor only,
  cipher set stays GCM-only), standards-backed (BSI TR-02102-2), and carries a
  2031 horizon.

A relaxation without a named reason is a defect, not a feature: a declared
restriction the runtime does not impose is a false anchor, and a relaxation no
one can name a reason for is indistinguishable from an accident.


## Enforcement is structural, not discretionary

Where strike imposes a security boundary, the boundary is enforced by the
controller, in code and types, on a path that cannot be opted out of.
There is no parallel configuration that disables it, no per-lane escape
hatch that weakens it, and no bypass channel beside it. A lane can request
more within a boundary -- more declared peers, a wider input set -- but it
cannot route around the mechanism that enforces the boundary, and it
cannot reach a capability by configuring strike to stop enforcing.

The pattern recurs throughout the architecture:

- Egress is mediated universally. Every container outbound connection
  passes through a controller-mediated path with a declared trust anchor;
  there is no raw-TCP allowlist, no plain-HTTP exception, and no
  compatibility mode. A new protocol is supported by adding
  controller-side mediator code, never by a lane-level opt-out.
- The hardened container profile is not lane-configurable. Capability
  drops, the read-only root filesystem, and no-new-privileges are fixed by
  the controller; a lane cannot weaken them.
- Peer trust has no per-peer opt-out. The declared peer list is the single
  source of truth for enforcement and attestation alike; there is no
  separate enforcement switch that could drift from it or be set to bypass
  it.

This is the complement of "restricted by default": that principle governs how
tight a default is and on what terms scope may widen; this one governs the
mechanism, which is never widened, disabled, or bypassed. A boundary a lane can
configure away is a suggestion, not a boundary -- and a suggestion cannot be
attested.


## Observation over declaration

A declaration is a claim about what should be true; an observation is a
record of what strike actually saw. Where the two diverge, the
observation governs. strike attests and acts on what it observed, never
on what was declared in its place, and a declaration the runtime does not
bear out is rejected rather than trusted. The signed record is therefore a
statement of fact, not of intent -- the only thing a downstream verifier
can check.

The pattern recurs throughout the architecture:

- The attestation records what happened, not what was intended: the engine
  identity and transport fingerprint as captured at the handshake, the
  resolved digests of the inputs actually pulled, the pre- and post-action
  state of a deploy as snapshotted -- not the lane's stated goal for any of
  them.
- The SBOM cataloger reads the compiled set from the binary's build info
  (`debug/buildinfo`, what `go version -m` reports), not the declared module
  graph (`go.mod`/`go.sum`): a required module that contributes no compiled code
  is not in the artifact and is not cataloged. The reachable surface is the real
  one; the module graph overstates it.
- A mediator certifies only what passed through it. Exhaustiveness of
  mediation is a declaration no record can support, so the attestation
  states observed passage, never a claim of completeness.
- Engine-verified facts (Layer V) outrank engine-asserted ones (Layer E):
  whether a fact was independently observed or merely declared by the
  engine is exactly what sets the trust layer it occupies.

This is the epistemic floor under "runtime is attested": that principle says
the runtime context is recorded; this one says the record is of the *observed*
context, and an observation always defeats a conflicting declaration.


## How the principles interact

The principles form a dependency chain. **Attestation requires
reproducibility** -- a signed attestation of a non-reproducible output is a
claim no one else can check. **Reproducibility requires digest pinning** -- a
build whose inputs drift cannot be byte-identical across runs. **Digest pinning
requires peer declaration** -- otherwise a step reaches arbitrary hosts and
artifact-level content addressing constrains nothing at execution time. **Peer
declaration requires identity asymmetry** -- conflating credential authorities
with trusted peers destroys distinctions the underlying protocols make. **Typed
secrets and CUE-first enforcement make the chain machine-checkable**; without
formal types, principles degrade into conventions.

The chain terminates at **no shell / no exec / no root**, which turn
attack-surface reduction from aspiration into structure -- and none of it holds
if code volume defeats the audit, which is why **code is liability** comes
first.


## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) -- trust boundaries, SLSA Build L3
  mapping, controller-engine protocol.
- [SECURITY.md](SECURITY.md) -- threat model and vulnerability reporting.
- [AGENTS.md](AGENTS.md) -- instructions for AI coding agents.
- [AI-WORKFLOW.md](AI-WORKFLOW.md) -- the human-AI collaboration model and
  authoring contract.
- [AI-ORCHESTRATION.md](AI-ORCHESTRATION.md) -- the orchestrate-only
  development model and the evidence behind its rules.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) -- code quality, style, and
  toolchain rules that implement these principles.
