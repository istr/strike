# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in strike, please report it
responsibly. **Do not open a public issue.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/istr/strike/security) of this
   repository.
2. Click **Report a vulnerability**.
3. Provide a description, steps to reproduce, and any relevant details.

You will receive an acknowledgement within 72 hours. We aim to provide a fix
or mitigation plan within 14 days of confirmation.

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

## Scope

The following are in scope for security reports:

- Container escape or privilege escalation via strike lanes
- Command injection through lane definitions, image references, or arguments
- Path traversal in tar extraction, source mounting, or output handling
- Secret leakage through process arguments, logs, error messages, or cache
  artifacts
- Digest verification bypass (image pinning, spec hash integrity)
- Supply chain issues in the bootstrap process or dependency chain
- Cryptographic weaknesses in signing or key handling
- SBOM integrity or attestation bypass

## Threat model

strike operates in a security-sensitive domain: it executes arbitrary container
images, handles signing keys, manages secrets, and interacts with OCI
registries. The threat model assumes:

**Trusted:** The lane definition author (the person writing `lane.yaml`) and
the host running strike. The lane definition is code -- it controls what images
run, what network access is granted, and what secrets are injected.

**Untrusted:** Container images (despite digest pinning, images may contain
malicious code), registry responses, and data flowing through step inputs and
outputs. A compromised or malicious step container must not be able to escalate
privileges, access secrets of other steps, modify its own inputs, or survive
past its exit.

**Semi-trusted:** The OCI registry. strike verifies image digests, but a
compromised registry could serve valid-looking but malicious content for
unverified artifact types.

### OWASP Top 10 mapping

The highest-risk categories for a CI/CD executor like strike:

**A03 Injection** -- The primary risk. strike invokes podman
as an external process. All invocations use `exec.Command` with separate
arguments (no shell interpretation). Lane definitions cannot inject shell
metacharacters because there is no shell. The command allowlist in the executor
restricts which binaries can be called.

**A08 Software and Data Integrity Failures** -- strike's core mission.
Unsigned container images must not leave the local store (enforced by the
unsigned-OCI-blocks-network guard). All external images must be digest-pinned.
SBOMs are attached as signed OCI 1.1 referrer artifacts. The bootstrap process
proves reproducibility through binary comparison.

**A02 Cryptographic Failures** -- Signing uses ECDSA P-256 via Go's
`crypto/ecdsa` with `crypto/rand`. Key derivation for encrypted cosign keys
uses scrypt with NaCl secretbox. No use of `math/rand` for security-relevant
operations. No TLS configuration overrides.

**A01 Broken Access Control** -- Step containers run with `--cap-drop=ALL`,
`--read-only`, `--security-opt=no-new-privileges`, and `--network=none` by
default. Output directories are mounted with `noexec,nosuid`. Inputs are
read-only.

**A05 Security Misconfiguration** -- The hardened security profile in
`internal/executor/step_security_profile.go` is not configurable by lane definitions.
Steps control only the image, arguments, environment, network flag, and
declared inputs and outputs.

**A06 Vulnerable and Outdated Components** -- `govulncheck` runs in CI and
reports only actually-reachable vulnerable functions. Dependencies are minimal
(~28 transitive).

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
- **Unsigned images cannot leave the local store** -- a network-enabled step
  that receives an unsigned OCI image input is rejected before execution.
- **Read-only root filesystem** -- step containers cannot modify their image.
- **No capabilities** -- `--cap-drop=ALL` removes all Linux capabilities.
- **No privilege escalation** -- `--security-opt=no-new-privileges` prevents
  setuid and setgid.
- **Output validation** -- declared outputs are validated against expected
  content types and size bounds.

## Container security profile

All step containers run with these flags (defined in
`internal/executor/step_security_profile.go`):

```
podman run \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --rm \
  --security-opt=no-new-privileges \
  --network=none \
  -v /host/out:/out:rw,noexec,nosuid \
  -v /host/input:/input:ro \
  image@sha256:... \
  arg1 arg2
```

What a step container **cannot** do: start nested containers, modify its own
image, execute from /out or /tmp, create setuid binaries, access the network
(unless explicitly granted), write anywhere except /out and /tmp, survive past
its own exit, or escalate privileges.

## User namespace mapping

All container steps run with `--userns=keep-id`. This maps the host user's UID
into the container as-is and passes the host's subuid/subgid range, enabling
nested rootless podman execution (e.g. for the stage_2 bootstrap step).

This does **not** grant additional capabilities. Seccomp and AppArmor profiles
remain active. An attacker who escapes an inner container reaches only
unprivileged host UIDs from the subuid range -- the same UIDs that rootless
podman already maps for any unprivileged user.

## Secret handling

Secrets flow through the system as follows:

1. Lane definitions reference secrets by name with a source URI
   (`env://VAR_NAME` or `file:///path`).
2. At execution time, strike resolves the source and holds the value in process
   memory only.
3. Secrets are passed to step containers as environment variables, injected via
   `--env NAME` with the value set in strike's process environment. This avoids
   the value appearing in `podman` command-line arguments (visible in
   `ps aux`).
4. Secrets are never written to disk, never included in cache artifacts, and
   never logged.

Future enhancement: secrets should be wrapped in a `SecretString` type that
overrides `String()`, `GoString()`, `Format()`, `MarshalText()`, and
`MarshalJSON()` to return `[REDACTED]`, providing type-level leakage
prevention.

## Security toolchain

The following tools run in CI on every change:

- **golangci-lint** with gosec enabled -- pattern-based and SSA-based security
  scanning (command injection, hardcoded credentials, insecure TLS, weak
  crypto, decompression bombs, path traversal).
- **govulncheck** -- official Go security team tool, reports only
  actually-reachable vulnerable functions in dependencies.
- **go test -race** -- detects data races in concurrent code.

## Container storage paths

The executor injects `XDG_RUNTIME_DIR=/tmp/run` and `XDG_DATA_HOME=/tmp/data`
into every container step. Container images that invoke podman internally will
automatically use `/tmp`-based storage paths, writable for any UID. This is
intentional and part of the execution model -- it ensures nested rootless podman
works regardless of the container image's default user or home directory layout.
