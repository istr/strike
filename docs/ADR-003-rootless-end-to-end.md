# ADR-003: Rootless End-to-End Execution

## Status

Accepted.

## Scope

This ADR concerns the controller and the host boundary: where
privileges live, what the host must provide, and what an attacker who
escapes a container can reach. Per-step container hardening (capability
drop, read-only root filesystem, no-new-privileges, network default)
is covered by ADR-005.

## Context

Container CI/CD tools commonly require root or a privileged daemon for
some part of their operation: the docker daemon historically ran as
root, kaniko needs CAP_SYS_ADMIN for chroot, buildkit's rootful mode
is widely deployed. Even tools that support rootless operation often
fall back to a root-bound daemon for "advanced" features. The
alternative -- rootless from start to finish, no privileged helper,
no setuid binary, no daemon -- requires accepting the constraints
that rootless container runtimes impose (user namespaces,
fuse-overlayfs or kernel overlay, subuid/subgid configuration).

Accepting those constraints removes an entire category of host-level
escalation paths. A rootless executor cannot escape its user namespace
into root on the host. A compromised step container that breaks out
of its container boundary lands in a user namespace, not on the host.
There is no daemon socket to poison, no setuid binary to hijack, no
privileged helper to subvert.

## Decision

strike runs end-to-end under a rootless container runtime. There is no
privileged helper, no setuid binary, no daemon process. The only host
dependency is a working rootless container engine (initially podman
with its user-mode socket).

The user namespace mapping is preserved across the controller-engine
boundary: containers are launched with `--userns=keep-id` so that file
ownership in mounted output paths matches the calling user. This is
the bridge between the rootless host model and the container
configuration; the per-container security profile that uses this
bridge is documented in ADR-005.

Storage driver selection inherits the rootless constraint: native
kernel overlay (kernel >= 5.13, non-overlay backing) is preferred,
fuse-overlayfs is the fallback, VFS is avoided because of its
disk-space and performance cost.

## Consequences

- The host requirement is exactly: rootless podman with socket
  enabled, plus subuid/subgid configured (standard rootless
  prerequisites). No CI agent, no Go toolchain, no daemon.
- A workload that requires a privileged helper, a setuid binary, or
  root-on-host access is out of scope. The right path is to refactor
  the workload, not to weaken the model.
- A container escape lands the attacker in an unprivileged user
  namespace. Further escalation requires a separate kernel
  vulnerability; the rootless boundary is not the only defense, but
  it is a defense that does not require any per-step configuration
  to be effective.
- Compatibility with non-systemd hosts (e.g. MX Linux with elogind)
  needs explicit handling because the podman user socket directory
  is not auto-created. Wrapper scripts must `mkdir -p
  "${XDG_RUNTIME_DIR}/podman"`. This is environment plumbing, not a
  weakening of the rootless model.

## Principles

- No root
- No exec (no privileged helper to spawn)
