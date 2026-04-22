# Design Principles

strike is a rootless, shell-free, container-native CI/CD executor. Its
architecture is derived from a small set of principles chosen to support
two goals simultaneously: **end-to-end software attestation and provenance
tracing**, and **systematic reduction of the supply-chain attack surface**.

These principles are the axioms of the project. Schemas, APIs, and
implementation details evolve. The principles are meant to be an invariant.
When a new feature or abstraction is proposed, the relevant question is not
whether it is useful but whether it is compatible with the principles.

The project is in pre-beta. Breaking changes at the schema and
implementation layer are expected and deliberate; principle-level drift
is not.


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
verifiable offline, without contacting strike or the original engine.


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
Timestamps follow `SOURCE_DATE_EPOCH`, file enumeration is
canonicalized, layer ordering is stable, and `time.Now()` is prohibited
in any path that affects artifact content. Without this property, the
cross-implementation verification that the CUE-first principle exists
to support cannot distinguish correctness from coincidence.


## Code is liability

Every line of strike is attack surface, maintenance cost, and a
candidate failure mode. The project resists abstraction for its own
sake, rejects dependencies that duplicate standard-library
functionality, and prefers a targeted small change to a framework hook.
"A little copying is better than a little dependency." This applies to
AI-generated contributions in particular: code bloat is a concrete
supply-chain concern, not an aesthetic one.


## How the principles interact

The principles reinforce each other in ways worth naming explicitly:

- **Attestation requires reproducibility.** A signed attestation of a
  non-reproducible output is a signed claim that no one else can check.
- **Reproducibility requires digest pinning.** A build whose upstream
  inputs drift cannot produce byte-identical outputs across runs.
- **Digest pinning requires peer declaration.** If a step can reach
  arbitrary hosts, content addressing at the artifact level does not
  constrain what the step actually does during execution.
- **Peer declaration requires identity asymmetry.** Treating credential
  authorities and trusted peers as one thing destroys the distinctions
  the underlying protocols make.
- **Typed secrets and CUE-first enforcement make the above
  machine-checkable.** Without formal types, principles degrade into
  conventions.

The chain terminates at **no shell / no exec / no root**, which turn
attack-surface reduction from aspiration into structure.


## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) -- trust boundaries, SLSA Build
  Level 3 mapping, and the controller-engine protocol.
- [SECURITY.md](SECURITY.md) -- threat model and vulnerability
  reporting.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) -- code quality, style,
  and toolchain rules that implement these principles.
- [AGENTS.md](AGENTS.md) -- instructions for AI coding agents.
