# ADR-033: SSH Peer Egress and Unified Capsule Mediation

## Status

Accepted. Completes the Phase-2 enforcement of
[ADR-028](ADR-028-step-container-egress-mediation.md) for the SSH
mediation pattern, supersedes in part D24 and D26 of the ADR-028
roadmap, and ratifies D27 and D28. Builds on
[ADR-031](ADR-031-pasta-splice-only-dependency.md) (pasta
`--splice-only` dependency), [ADR-024](ADR-024-ssh-known-hosts.md)
(SSH server trust), and [ADR-025](ADR-025-ssh-agent-proxy.md) (SSH
client identity).

## Context

ADR-028 specified three mediation components and two patterns: TLS
(terminated at a per-step mediator) and SSH (the controller forwards
the TCP connection; the container's SSH client verifies the server
against a mounted known_hosts file, and client identity is delegated
to the agent proxy). The TLS pattern shipped in PR-22; the SSH pattern
did not. SSH steps continued to run with `--network=bridge`, which
gives the container unrestricted outbound network. A step that
declared an SSH peer could reach any host on the network, not just the
declared peer -- the "peers are declared" guarantee held for HTTPS but
not for SSH.

The egress backend uses pasta `--splice-only` with `-T`/`-U` forwards.
pasta's `-T`/`-U` accept no listening address, so per-step distinctness
lives in the host-side port and the container always sees fixed
loopback addresses. HTTPS peers share one container-side port (443)
because the mediator demultiplexes by TLS SNI. SSH carries no name that
strike interprets without parsing the protocol, so SSH peers cannot
share a single port the way HTTPS peers do.

## Decision

### D27: SSH peer egress via per-peer port-mux

Each SSH peer of a step gets its own container-side loopback port and
its own host-side raw-TCP forward through the step's capsule.

- The container-side port is strike-assigned, `SSHContainerPortBase +
  k` for the k-th SSH peer in peer-list order, and is never 22. Port 22
  is deliberately left unforwarded. A connection that ignores the
  injected configuration reaches no forward and fails closed; it is not
  misrouted to another peer.
- strike injects the per-peer port mapping as an `ssh_config` with one
  `Host` block per peer setting only `Port`. `HostName` is not
  overridden, so name resolution flows through the capsule resolver and
  is attested. The file is bind-mounted and referenced via `-F` in the
  `GIT_SSH_COMMAND` established by ADR-024/025.
- The host-side forward is a raw TCP splice. strike resolves the
  declared upstream host via the lane's DoT resolver, dials the
  resolved address at the peer's port (default 22), and copies bytes in
  both directions. strike does not terminate, decrypt, or inspect the
  SSH stream. Server trust remains with the container's SSH client
  against the mounted known_hosts (ADR-024); client identity remains
  with the agent proxy (ADR-025).
- The forward records one connection record per attempt (timestamp,
  declared host, resolved IP, port, outcome) for the attestation
  surface ADR-028 specifies for SSH peers.

The injected `ssh_config` is an ergonomic aid, not the security
boundary. The boundary is the egress filter (`--splice-only` plus the
explicit forward set) and the resolver allowlist, both derived from the
declared peer list. This is the SSH analog of TLS mediation: client
identity at the controller, server identity against the declared
anchor, egress restricted to declared peers.

### D28: every step container runs under a capsule

The `--network=none` and `--network=bridge` modes are removed. Every
step container runs under a per-step `NetworkCapsule` with pasta
`--splice-only`. A peer-less step gets a capsule with an empty
allowlist: the resolver answers NXDOMAIN for every name, the mediator
denies every SNI, and pasta carries only the resolver and mediator
forwards. This is equivalent to `--network=none` for egress (no path
reaches any real upstream) but gives every step the same diagnostic
surface (denied resolves and connects are recorded) and removes the
mode switch.

This applies uniformly to all four container code paths: run-step
execution, state capture, Kubernetes deploy, and custom deploy. Pack
steps assemble images controller-side, launch no step container, and
are unaffected. The registry deploy method runs no container.

### Address space as a deliberate cost

Each container unit consumes a contiguous block of host ports
(`2 + SSH-peer-count`), allocated deterministically in lane-file order.
This is a conscious cost of the rootless, no-daemon, default-deny
posture: without a privileged helper or a long-lived daemon, strike
cannot install kernel-level DNAT rules, so it forwards specific ports
to controller-side listeners. The host-port budget (above 5353) is
large relative to any realistic lane.

### Why not netavark or a CNI plugin

A netavark firewall or a custom CNI plugin installing nftables rules at
namespace creation could express "DROP all, redirect 53 and 443"
without per-peer port forwards. Both were rejected for Phase 2: they
require either root or a privileged helper at namespace setup, which
violates "no root", and they add a substantial external dependency
surface for a capability `--splice-only` already provides structurally.
The port-mux cost is paid in host-port consumption, not in privilege or
dependency.

## Consequences

- "Peers are declared" is now structurally true for SSH as it already
  was for HTTPS. An SSH step reaches only its declared peers.
- The deploy paths (state capture, Kubernetes, custom) gain the same
  mediation as run steps. The `Deployer` carries the ephemeral CA, the
  DoT lookup, the CA-bundle path, and the pre-allocated host ports.
- SSH connection metadata is captured for attestation. The validated
  host key already lives in the lane's known_hosts entry, so the record
  confirms the connection succeeded against that entry.
- Lanes mixing HTTPS and SSH peers in one step now work directly; they
  no longer need to be split. The former roadmap items PR-23 (mixed
  HTTPS+SSH) and PR-24 (SSH under the unified roof) are subsumed here.

## Open follow-ups

- **SSH client-config delivery.** strike currently injects the
  ssh_config via a `-F` token appended to a strike-imposed
  `GIT_SSH_COMMAND`. The cleaner end state mirrors the TLS CA: strike
  bind-mounts the transport config at the system-wide ssh path so a
  native tool reads it without an env override, and a tool that ignores
  it is nudged explicitly in the lane (the npm `--cafile` pattern).
  Migrating known_hosts and StrictHostKeyChecking enforcement off
  `GIT_SSH_COMMAND` onto system-path injection, and dropping
  `GIT_SSH_COMMAND` if then unnecessary, is deferred.
- **Per-peer SSH connection attestation schema.** The forward records
  connection metadata; wiring it into the signed deploy attestation
  envelope follows the per-peer `connections` surface tracked in
  ADR-028.

## Principles

- Peers are declared (now enforced for the SSH egress dimension).
- Identity is asymmetric (server trust via known_hosts, client identity
  via agent proxy, both unchanged; strike forwards but does not
  terminate SSH).
- No root (pasta `--splice-only`, no privileged helper, no daemon).
- Runtime is attested (SSH connection metadata captured per attempt).
- Code is liability (one raw-TCP forwarder; no SSH parsing, no protocol
  re-implementation, no inspection).
