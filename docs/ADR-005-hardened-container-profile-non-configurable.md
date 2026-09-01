# ADR-005: Hardened Container Profile, Not Lane-Configurable

## Status

Accepted.

> **Amended by [ADR-022](ADR-022-network-opt-in-as-peer-list.md),
> applied in place:** unlike every other revision note in this corpus,
> the Decision text below is already the revised text. Commit 523c5d6
> (2026-05-02, "feat: Introduce qualified peers instead of network
> boolean switch") rewrote this ADR in place when ADR-022 replaced the
> network boolean with the typed peer list. The network bullet
> previously read: "`--network=none` -- network disabled unless
> `network: true` is set on the step. The opt-in surface is one bit,
> visible in the lane source." -- and the "network bit" wording in the
> not-configurable paragraph and the Consequences was replaced
> alongside it. That edit contradicts the content-stability rule the
> index states (revision by a later ADR, never by editing the original
> decision). This note is the marker that edit should have been, added
> retroactively so the record is legible again: ADR-022's statement
> that "ADR-005's 'the opt-in surface is one bit' sentence is now
> historical" refers to the pre-revision sentence quoted here, and the
> Decision's forward reference to ADR-022 stems from the in-place
> revision, not from the original text.

> **Amended by [ADR-033](ADR-033-ssh-peer-egress-and-unified-mediation.md):**
> the "`--network=none` by default" wording is itself historical:
> ADR-033 D28 removes the network modes -- every step container,
> peer-less ones included, runs under a per-step capsule (a peer-less
> step's capsule resolver answers NXDOMAIN for every name), so the
> default is capsule mediation, not a `--network` flag. The decision
> stands: the hardened profile is non-configurable, and network
> access remains opt-in via the declared peer list.

## Scope

This ADR concerns the security profile of individual step containers
-- what each step is permitted to do once it starts running. The
end-to-end rootless model that prevents privilege escalation to the
host is covered by ADR-003.

## Context

Every step in strike runs in a container. Once the rootless boundary
(ADR-003) ensures that no step can reach root on the host, a second
question remains: within the per-step container, what can a
compromised step do? A step container that runs with default Linux
capabilities, a writable root filesystem, ambient network access, and
permission to escalate privileges has substantial attack surface even
without crossing the host boundary -- it can mount filesystems
visible to it, modify its own image layers, reach arbitrary network
peers, and acquire setuid binaries.

CI/CD systems often expose these knobs to lane authors: a step can
request additional capabilities, a writable root filesystem, host
network, or privileged mode, because some legitimate workloads need
them. Exposing the knobs in the lane definition language means the
hardening becomes optional. Every step that *could* run in a hardened
profile *might not*, depending on what the lane author wrote, and the
attack surface across the lane becomes whatever the most permissive
step requested.

The alternative is to fix the security profile at the controller and
refuse to expose it as configuration. Workloads that do not fit the
profile are out of scope.

## Decision

Every step container runs with:

- `--cap-drop=ALL` -- no Linux capabilities;
- `--read-only` -- root filesystem is read-only; outputs go to
  declared output mounts which are noexec/nosuid;
- `--security-opt=no-new-privileges` -- no setuid escalation inside
  the container;
- `--network=none` by default. Steps opt into network access with a
  declared peer list (`peers: [...#Peer]`); see ADR-022. The opt-in
  surface is visible in the lane source and recorded in the
  attestation.

The user-namespace mapping (`--userns=keep-id`) is set per ADR-003
and is not part of this profile -- it is the host-boundary plumbing
that lets the per-container hardening land correctly on a rootless
host.

The profile is encoded as `container.RunOpts` fields in
`internal/executor/podman.go` and is not configurable from lane
definitions. Steps control: image, arguments, environment, the
declared peer list, declared inputs and outputs, declared workdir.
They control nothing else about the security profile.

## Consequences

- A workload that genuinely needs an additional capability or a
  writable root filesystem is out of scope. The path forward is to
  refactor the workload (often by splitting it into steps that do
  the capability-requiring work in a different way, or by replacing
  it entirely with a containerized primitive).
- Lane authors cannot weaken security by accident or under deadline
  pressure. The strongest profile is the only profile.
- Reviewers reading a lane definition do not have to audit the
  security profile per-step; they can trust that every step has the
  same profile and only verify the declared peer list and mounts.
- The opt-in for network surfaces in three places: the lane source,
  the deploy attestation, and the typed peer declaration (ADR-022).
  ADR-007 mandates trust anchors per declared peer; ADR-022
  realises the schema. ADR-003 ensures the network opt-in cannot be
  silently bypassed by a privileged helper, because there is no
  privileged helper.

## Principles

- No root
- Code is liability (no configuration knobs to misuse)
- Peers are declared (network is opt-in, with the opt-in visible in
  the lane source)
- **Enforcement is structural, not discretionary.** The hardened profile
  is fixed by the controller; a lane cannot weaken capability drops, the
  read-only root, or no-new-privileges.
