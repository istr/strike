# ADR-025: SSH Peer Client-Identity Enforcement

## Status

Accepted.

## Scope

This ADR concerns enforcement of the SSH client-identity dimension
of ADR-022's typed peer list: how strike delegates SSH client
authentication to a credential-holding authority. It is the
companion to ADR-024 (SSH server-trust enforcement). Per ADR-007,
server identity and client identity are asymmetric and arrive
through separate mechanisms; this ADR establishes the second
mechanism.

## Context

ADR-024 closed the server-trust gap: containers with declared SSH
peers now do strict host-key checking. Operators report that
this is sufficient to negotiate the SSH connection but
insufficient to authenticate the client. A `git pull` over
`git+ssh` reaches the server and is rejected with
`Permission denied (publickey,...)` because no client identity is
reachable inside the container.

ADR-007 defines the architectural posture for client identity:

> Credential-holding authorities such as ssh-agent, KMS, or OIDC
> workload identity delegate signing power without revealing key
> material; strike mediates but does not own the keys.

"Without revealing key material" is not a soft preference. A
mechanism that materialises a private key onto a container
filesystem -- even read-only, even short-lived -- breaks the
principle definitionally: the bytes of the private key exist
inside a process boundary that strike does not control. Once
materialised, exfiltration depends on container isolation and
image trust, neither of which strike is positioned to underwrite.

The ssh-agent protocol is the canonical fit. The agent holds the
private key in its own process; signing requests cross a Unix
domain socket; the requester learns the public key and the
signature, never the private key.

## Decision

When a step declares at least one `lane.SSHPeer` and the strike
process has `SSH_AUTH_SOCK` set in its environment, strike
performs the following before the container starts:

- Creates a per-execution proxy Unix domain socket in the
  step's scratch directory at mode `0o666`. The scratch
  directory itself is mode `0o700`, so the socket is reachable
  only by the host user that owns the strike process.
- Starts a goroutine that accepts connections on the proxy
  socket and forwards each accepted connection bidirectionally
  (`io.Copy` in both directions) to the host's real ssh-agent
  socket at `SSH_AUTH_SOCK`. The forwarder is scoped to the step
  context and shuts down when the step ends.
- Bind-mounts the proxy socket at `/run/strike/ssh-agent.sock`
  inside the container. The bind mount is read-write because
  agent traffic is bidirectional; the socket inode itself is
  ephemeral and host-side.
- Adds `SSH_AUTH_SOCK=/run/strike/ssh-agent.sock` to the
  container environment.
- Extends the `GIT_SSH_COMMAND` value established by ADR-024
  with `-o BatchMode=yes` so OpenSSH never blocks on an
  interactive prompt in a container that has no TTY.

When a step declares at least one `lane.SSHPeer` and the strike
process does **not** have `SSH_AUTH_SOCK` set, strike fails the
step before the container starts with a message of the form

    ssh peer "<host>" declared but SSH_AUTH_SOCK not set
    in strike process environment

This is fail-fast: no warning, no silent skip, no automatic
fallback.

When a step declares no SSH peers, none of the above happens.
The container sees no proxy socket, no agent env var, and the
`GIT_SSH_COMMAND` injection from ADR-024 is absent.

The proxy forwarder does not inspect, filter, log, or otherwise
observe the bytes flowing through it. Agent traffic includes
hashes of payloads being signed, which is sensitive data; strike
mediates but does not record.

This applies to the same four container code paths covered by
ADR-024: run-step execution, state-capture execution, Kubernetes
deploy methods, and custom deploy methods. The registry deploy
method is unchanged for the same reason: it runs no container.

## What is explicitly excluded

The following alternatives are not "deferred until a concrete
case appears". They are structurally outside strike's design:

- **Typed deploy keys delivered via lane secrets.** A lane could
  in principle declare a private key as a secret, and strike
  could in principle materialise it onto the container
  filesystem as `~/.ssh/id_*`. Strike will not do this. The
  bytes of a private key on a container filesystem violate
  ADR-007 definitionally; the principle does not bend to
  convenience. A lane author who has only a file-based key and
  no agent must load that key into an agent on the host before
  invoking strike.
- **Key generation inside strike.** Strike does not generate SSH
  keys, ephemeral or otherwise. Key custody belongs outside the
  controller.
- **Container-internal agents.** Strike does not start an
  `ssh-agent` inside the step container, populate it from any
  source, or rely on per-container agent state. The agent
  authority is the host's agent, accessed through the proxy.

## What is deferred

These are open architectural questions for future ADRs, not
exclusions:

- **KMS-based client identity** (signing requests against a KMS
  endpoint rather than ssh-agent). Same asymmetric-identity
  shape; different transport.
- **TPM-resident keys** surfaced through the local agent or a
  PKCS#11 bridge. Requires no strike change if the agent already
  presents them.
- **OIDC workload identity** for non-SSH client authentication
  (HTTPS peers, OCI registries). Separate transport, separate
  ADR.
- **Agent identity filtering** so a step sees only a subset of
  the agent's keys. The principle is sound; no use case yet
  demands it.

## Consequences

- A working `git+ssh` step requires (1) a typed `#SSHPeer` with
  `known_hosts` entries, and (2) a running ssh-agent on the host
  with the necessary client key loaded. Both prerequisites are
  the operator's, not strike's; strike's job is to wire them
  together.
- The step container's user identity remains whatever the image
  or the lane prescribes. Strike does not override `--user` to
  match the host UID. The proxy socket's `0o666` mode makes the
  forwarder reachable regardless of the container UID under
  `--userns=keep-id`, which closes the UID-mapping pitfall
  without forcing step-author hands.
- Strike's process becomes the agent's proxy for the lifetime of
  any step with SSH peers. A crashed strike process is a
  terminated agent connection; this is the correct failure mode.
  No agent state persists beyond the step.
- The proxy is per-step, not per-lane. Two steps in the same
  lane each get their own scratch socket; neither sees the
  other's traffic. The cost (one extra goroutine per SSH step)
  is negligible against the clarity of lifecycle.
- The fail-fast posture when `SSH_AUTH_SOCK` is missing is
  intentional. A silent fallback that "tries without an agent"
  would produce an opaque `Permission denied` at the SSH server
  rather than a clear error from strike. Operators get a precise
  message at the earliest point.

## Principles

- Identity is asymmetric (client identity is delegated to an
  external authority; server identity stays in the typed peer
  declaration per ADR-024)
- No root (the proxy socket is created and accessed under the
  host user; no privileged operation)
- Code is liability (one proxy goroutine; no agent
  re-implementation, no key handling, no payload inspection)
- Peers are declared (the SSH peer declaration is the opt-in;
  agent forwarding follows mechanically)
- **Enforcement is structural, not discretionary.** Client identity
  stays at the controller via the agent proxy; the container never holds
  key material and cannot opt out.
