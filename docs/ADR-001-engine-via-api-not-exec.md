# ADR-001: Container Engine via REST API, Not Subprocess Execution

## Status

Accepted.

## Context

A container-native CI/CD executor must drive a container engine (podman,
docker, containerd) to run build and deploy work. Three approaches are
common:

- *Exec a binary.* The controller calls `podman run ...` as a subprocess.
- *Embed a Go library.* The controller imports the engine as Go code
  (e.g. containerd's libraries) and runs containers in-process.
- *REST/socket API.* The controller talks HTTP to the engine over a Unix
  socket or TLS-secured TCP.

Each has implications for SLSA Build Level 3 compliance. The exec path
shares the parent process environment (including signing keys and OIDC
tokens) with every invoked binary, fails L3 key isolation, and leaves
the controller vulnerable to PATH hijacking, LD_PRELOAD attacks, and
binary replacement. The embedded-library path passes L3 nominally but
collapses every layer's security posture into a single compromised
process. The API path isolates key material in the controller and
treats the engine as an untrusted worker.

## Decision

strike communicates with the container engine exclusively via the REST
API over Unix socket or TLS-secured TCP. There are zero `os/exec`
imports in the codebase. Security-sensitive operations (OCI image
assembly, signing, SBOM generation, attestation construction) use
native Go libraries within the controller process. Build workload
execution happens in containers reached through the engine API.

## Consequences

- The controller signs only digests it has independently verified.
  Engine self-reports are not trusted.
- State capture, kubectl, HTTP probes, and all other "external"
  operations run as container steps, not as host processes.
- A compromised engine cannot read controller secrets; it can return
  bad data, which the controller catches via independent verification.
- Linting (depguard, forbidigo) enforces the no-`os/exec` invariant
  at CI time, not by review discipline.
- Adding a new external operation requires either a Go library
  integration or a containerized step. There is no third option.

## Principles

- No exec
- No shell
- Code is liability
