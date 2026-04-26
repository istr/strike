# ADR-020: Storage Driver Selection and Host Environment Plumbing

## Status

Accepted.

## Context

Rootless container engines have a harder storage-driver problem than
rootful ones. The kernel's native overlay filesystem requires
specific kernel features and a non-overlay backing filesystem; on
systems where it is not available, the fallback is fuse-overlayfs
(slower, requires the FUSE module) or VFS (functional but copies
every layer file, an order of magnitude slower). The choice affects
both performance and correctness: an overlay backing on overlay
backing produces hard-to-diagnose storage errors.

This decision interacts with host environment specifics that ADR-003
took as out-of-scope but that practical operation cannot ignore:

- Distributions without systemd (e.g. MX Linux, Devuan, Alpine
  init) do not auto-create `${XDG_RUNTIME_DIR}/podman` because the
  systemd-tmpfiles unit that does this on most distros is absent.
- Subuid/subgid configuration must be present and correct;
  misconfigurations produce permission errors that look like bugs
  but are environmental.
- Cgroups v2 is required for full rootless support; cgroups v1
  hosts work in degraded modes that strike does not specifically
  test against.

These are not strike's bugs. They are the boundary conditions of
the rootless container ecosystem. The question is whether strike
documents them, papers over them, or ignores them.

## Decision

Storage driver selection follows this preference order:

1. **Native kernel overlay.** Kernel >= 5.13 with a non-overlay
   backing filesystem (typical on ext4, XFS, Btrfs root).
2. **fuse-overlayfs.** Available on most distributions as a
   package; slower than native overlay but correct.
3. **VFS.** Functional fallback; not recommended for routine use.

Strike does not configure podman's storage driver itself. The
decision is made by podman based on its detection of host
capabilities. Strike's contribution is to document the preference
order so that operators encountering performance issues know what
to check.

For host environment plumbing that strike's bootstrap requires but
does not enforce:

- The `XDG_RUNTIME_DIR` directory must exist and be owned by the
  invoking user. Wrapper scripts should `mkdir -p
  "${XDG_RUNTIME_DIR}/podman"` before invoking strike on hosts
  without systemd-tmpfiles.
- Subuid/subgid configuration is the operator's responsibility.
  Strike emits a clear error if container creation fails due to
  uid mapping issues, but does not attempt to repair the
  configuration.
- Cgroups v2 is assumed. Hosts running cgroups v1 may produce
  resource-limit errors that strike reports verbatim from podman.

The bootstrap Containerfile uses native podman defaults inside the
builder image. The host running the bootstrap is responsible for
the prerequisites listed above; strike's bootstrap stages do not
attempt to configure them.

## Consequences

- Hosts that meet the prerequisites (modern kernel, ext4/XFS/Btrfs
  root, cgroups v2, systemd or a correctly-configured replacement)
  run strike with no additional setup.
- Hosts that do not meet the prerequisites get readable error
  messages pointing at the missing piece, not silent failures or
  partial operation. The error path is the documentation surface
  for environmental issues.
- Strike's own code does not contain host-detection logic for
  storage drivers, init systems, or cgroup versions. The container
  engine handles these; strike reads its responses and reports
  them.
- Operators on non-systemd distributions need a small wrapper
  script to ensure `XDG_RUNTIME_DIR/podman` exists before invoking
  strike. This is documented in `docs/local-development.md` for
  the local-iteration workflow; for CI environments, the wrapper
  is part of the runner image setup.
- The decision to defer to podman for storage-driver selection
  means strike inherits podman's correctness on this dimension.
  If podman makes a wrong choice on a particular host, the fix is
  to upgrade podman or override its configuration directly, not to
  patch strike.

## Principles

- No root (rootless storage drivers are the only ones supported)
- Code is liability (no host-detection logic; the container engine
  already knows)
- External references are digest-pinned (the bootstrap base image
  is pinned by digest, isolating strike from the host's package
  versions)
