# ADR-005: Hardened Container Profile, Not Lane-Configurable

## Status

Accepted.

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
- `--network=none` -- network disabled unless `network: true` is set
  on the step. The opt-in surface is one bit, visible in the lane
  source.

The user-namespace mapping (`--userns=keep-id`) is set per ADR-003
and is not part of this profile -- it is the host-boundary plumbing
that lets the per-container hardening land correctly on a rootless
host.

The profile is encoded as `container.RunOpts` fields in
`internal/executor/podman.go` and is not configurable from lane
definitions. Steps control: image, arguments, environment, the
network bit, declared inputs and outputs, declared workdir. They
control nothing else about the security profile.

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
  same profile and only verify the network bit and declared mounts.
- The opt-in for network surfaces in three places: the lane source,
  the deploy attestation, and the declared-peers contract. ADR-007
  builds on this to require trust anchors per declared peer; ADR-003
  ensures the network opt-in cannot be silently bypassed by a
  privileged helper, because there is no privileged helper.

## Principles

- No root
- Code is liability (no configuration knobs to misuse)
- Peers are declared (network is opt-in, with the opt-in visible in
  the lane source)
