# Security Policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

## Reporting a vulnerability

If you discover a security vulnerability in strike, please report it
responsibly. **Do not open a public issue.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/istr/strike/security) of this
   repository.
2. Click **Report a vulnerability**.
3. Provide a description, steps to reproduce, and any relevant details.

You will receive an acknowledgement within 72 hours. We aim to provide a fix
or mitigation plan within 14 days of confirmation.

## Scope

The following are in scope for security reports:

- Container escape or privilege escalation via strike lanes
- Secret leakage through process arguments, logs, or cache artifacts
- Digest verification bypass (image pinning, spec hash integrity)
- Supply chain issues in the bootstrap process

## Design principles

strike is designed with a minimal attack surface:

- **No shell execution** -- steps are exec'd directly, no interpreter involved.
- **No root** -- runs entirely under rootless podman.
- **No network by default** -- steps run with `--network=none` unless
  explicitly opted in with `network: true`.
- **Digest pinning** -- all external images must be referenced by SHA-256
  manifest digest.
- **Secrets via environment only** -- never written to process arguments or
  persisted to disk.

## User namespace mapping (`--userns=keep-id`)

All container steps run with `--userns=keep-id`. This maps the host user's UID
into the container as-is and passes the host's subuid/subgid range, enabling
nested rootless podman execution (e.g. for the stage_2 bootstrap step).

This does **not** grant additional capabilities. Seccomp and AppArmor profiles
remain active. An attacker who escapes an inner container reaches only
unprivileged host UIDs from the subuid range -- the same UIDs that rootless
podman already maps for any unprivileged user.

## Container storage paths (`XDG_RUNTIME_DIR`, `XDG_DATA_HOME`)

The executor injects `XDG_RUNTIME_DIR=/tmp/run` and `XDG_DATA_HOME=/tmp/data`
into every container step. Container images that invoke podman internally will
automatically use `/tmp`-based storage paths, writable for any UID. This is
intentional and part of the execution model -- it ensures nested rootless podman
works regardless of the container image's default user or home directory layout.
