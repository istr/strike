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
