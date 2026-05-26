# ADR-038: Protocol-Mediated SSH via a Control-Plane Front

## Status

Accepted.

Supersedes the SSH handling of [ADR-024](ADR-024-ssh-peer-server-trust-enforcement.md)
(container-mounted `known_hosts`), [ADR-025](ADR-025-ssh-peer-client-identity-enforcement.md)
(agent socket forwarded into the container), and the SSH portions of
[ADR-028](ADR-028-step-container-egress-mediation.md) /
[ADR-033](ADR-033-ssh-peer-egress-and-unified-mediation.md) (raw TCP-forward
relay, per-peer host-port mux). Refines [ADR-007](ADR-007-asymmetric-identity.md).

Built on the trust-layer classification of
[ADR-037](ADR-037-two-engine-trust-layers.md). D7's notarization scope is an
application of ADR-037 D2 (no-false-positive Layer V vs. completeness Layer E,
and the no-mixing provenance rule); the credential-custody trajectory in D3 is an
application of ADR-037 D5.1 (signing/credential authority externalized from any
party not in the trusted base); the front's location is forced by ADR-037 D5
(no moving Layer-V production onto the engine).

## Scope

How a step container reaches an SSH-transported upstream, and how that
connection is mediated and attested, with the engine either local or remote. The
first supported protocol is git over SSH; scp, sftp, and rsync over SSH are
intended to follow through the same mechanism (D1). This ADR restructures the
mediation subsystem (the front and the per-step capsule context) in a way that
also carries HTTPS and DoT; the HTTPS *trust* rules of ADR-028 are unchanged,
only their hosting moves. The strike-to-engine control channel (the Podman API
connection) is a separate channel and is out of scope here.

## Context

Today's SSH path couples three mechanisms to "controller and engine on the same
host":

- `known_hosts` for the upstream peer is bind-mounted into the container, and the
  container's own SSH client validates the server (ADR-024).
- Client identity is delegated by forwarding the host ssh-agent socket *into* the
  container (ADR-025).
- Egress is a raw TCP forward: strike does not terminate SSH, the container is the
  SSH client end to end, and per-peer host ports disambiguate which loopback
  forward reaches which peer (ADR-033).

When the engine is remote, and on closer inspection regardless of locality, this
has four problems:

1. **Host-locality.** The forwarded agent socket and the loopback port-mux only
   work when the container and the controller share a host. Neither survives a
   remote engine.
2. **No protocol restriction.** Because the relay never terminates SSH, the
   command the container runs over the channel (`git-upload-pack`, a shell, a
   port-forward, an arbitrary binary) is encrypted past the key exchange and
   invisible to strike. "Only git" is hoped for, not enforced; a compromised step
   can request a shell on any reachable declared peer.
3. **In-container signing oracle.** The forwarded agent socket lets a hostile
   container use the host key to authenticate arbitrary SSH sessions to any
   reachable host, and to request signatures over chosen blobs, bounded only by
   egress. This is the classic agent-forwarding hazard sitting inside the
   untrusted container.
4. **Per-step port-mux as inbound surface.** The port-mux is a host-port-consuming
   crutch. For a remote engine, keeping it would mean exposing a *port range* as
   inbound surface on the control plane, the opposite of what is wanted across an
   engine-to-strike network boundary.

The content-integrity argument is settled elsewhere and is *not* the driver here:
a git input is a commit digest pin (ADR-011), so a wrong or MITM'd server cannot
produce a commit that passes the pin. The drivers are surface reduction (problems
2, 3), engine-location independence (1), and minimal inbound surface (4).

A bounded spike (control-plane front step-demux) settled one feasibility
question this design rests on: on rootless Podman with pasta, all container
egress collapses to the host's source address at the netns boundary, so a
control-plane front cannot recover per-container identity from the network. Step
demultiplexing must therefore be carried in-band, not by source identity.

## Decision

### D1: Generic SSH is dropped; only protocols over SSH are supported

strike no longer mediates generic SSH. It mediates specific protocols that use
SSH as a transport, identified by an allowlist of remote commands and subsystems.
The initial allowlist is `git-upload-pack` and `git-receive-pack`. `sftp`
(subsystem), `rsync --server`, and `scp -t`/`scp -f` are the intended later
additions through the same mechanism.

Anything not on the allowlist (an interactive shell, an arbitrary command, SSH
port forwarding, agent forwarding) is refused. The allowlist *is* the supported
protocol surface. This is the intended behaviour, not a regression to be patched
around, and it is consistent with ADR-028's "tools that cannot use the
system-configured transport are not supported".

### D2: Two components -- a run-level front and a per-step capsule context

The mediation subsystem is split into two layers, both in the control plane.

**The front** is a single, run-level, control-plane component. It is the one
inbound endpoint the data plane reaches: it terminates the container-facing
sessions (SSH, TLS, DoT), reads the in-band step+peer selector (D5), and
dispatches each connection to the right per-step capsule context. Because it
terminates, it holds run-level ephemeral crypto material (one SSH host key, one
TLS CA per lane run; D3). The front is *not* a dumb L4 forwarder: SSH carries no
pre-key-exchange signal, so the selector is only readable after termination, and
termination must therefore be the front's, run-level (see D5).

**The per-step capsule context** is retained as a first-class per-step type, held
in-process by the front, one per active step. It owns that step's *policy*: the
declared peer set and their trust anchors, the upstream-dial logic, the
allowlist. It does **not** own a container-facing listener or its own crypto
endpoint any more; those lifted to the front. The capsule's policy structure is
otherwise unchanged from the per-step capsule of ADR-028/033 -- this is a
rewiring, not a rewrite of the filter logic.

The per-step capsule context is in-process state, not a separate process. n
concurrent steps are n goroutine-scoped contexts, the Go-idiomatic shape;
per-connection panic recovery and per-step resource budgets give the fault and
resource containment that separate processes would, without IPC, lifecycle
management, or an internal plaintext-proxy hop. (A separate-process variant is
recorded under rejected alternatives; it is a reversible later change if
operational evidence demands OS-level isolation, because the context is already a
clean, self-contained type.)

The engine-side per-step pasta instance is unchanged and stays per step: it locks
each container's egress to the front's address. That is Layer-E enforcement,
engine-applied, untrusted, and orthogonal to everything above.

### D3: Run-level termination, controller-side identities (refines ADR-007/024/025)

**Near-side server identity.** The front presents a single *ephemeral per-lane-run
host key* (and, for TLS, a single per-run ephemeral CA). Every declared peer
hostname maps, in the container's synthetic `known_hosts` (and trusted-CA set),
to that one front identity. This is the SSH analog of the ephemeral per-run TLS
CA (ADR-028): the container does strict host-key checking against an anchor strike
controls, not against the real peer. Per-step crypto isolation is deliberately
not attempted: the front is a single TCB component holding all live secrets for
the run regardless, so per-step keys would buy little; what survives per step is
*policy* isolation (D2), enforced by the dispatch table, which is the isolation
ADR-025 actually required ("neither sees the other's traffic").

**Upstream server identity.** The declared `known_hosts` trust anchor is validated
by the front's upstream client, controller-side. The real peer's `known_hosts` is
no longer mounted into the container.

**Upstream client identity.** The front authenticates the upstream connection from
a credential-holding authority. Step 1 uses the host ssh-agent, reached by the
front directly (never forwarded into the container). The later step externalizes
this to a KMS / keyless authority per ADR-037 D5.1; the container-facing mechanics
in this ADR do not change when the credential source does. The container holds no
key material (ADR-007 unchanged) and presents `none` to the front; near-side
reachability is gated by network isolation (D4) and the capability token (D5),
not by a container-held credential.

**Consequence (the principal security gain).** The in-container agent socket of
ADR-025 is removed, eliminating the latent in-container signing oracle (Context
problem 3): the key is used only by the front, only for the specific allowlisted
upstream operation, only after the upstream host-key anchor is validated.
`SSH_AUTH_SOCK` is absent in the container; the ADR-025 fail-fast on a missing
agent inverts.

### D4: Redirection by DNS, enforcement by topology

The container's view of every peer hostname resolves, through strike's controlled
resolver, to the single front endpoint. The container's client connects there
believing it reached the peer. This is mediation-by-redirect, the SSH/TLS analog
of the existing HTTPS path, and unlike the loopback port-forward it is
engine-location-independent: the redirect target is a routable front address, not
a same-host loopback port. The container's pasta instance locks egress to that
address.

DNS redirection routes *cooperative* clients only; it is not an enforcement
boundary. The "no egress except via the front" property is a network-topology
guarantee (an internal network with no other route), a Layer-E property
engine-trusted per ADR-037 D4. A hostile container that ignores the resolver and
dials a hard-coded address is not prevented by DNS; it is prevented, if at all, by
topology, and any traffic it gets out that way is simply not mediated and not
notarized. This is the honest boundary of ADR-037 D2, not a defect.

The resolution recorded in the attestation is strike's *upstream* resolution
(peer hostname to real IP, performed controller-side), not the synthetic
container-facing answer.

The DoT resolver is itself a front endpoint. It is declared once per lane
(ADR-028), so it lifts to the front naturally. It carries no in-band token (a DNS
query has no `SetEnv` channel), so it cannot demultiplex by step; it resolves any
lane-declared hostname to the front and leaves per-step peer gating to the front's
token dispatch (D5). The only consequence is that the per-step *resolution*
allowlist relaxes to lane level: a container can *resolve* any lane peer's
hostname, but can *reach* only the peers whose tokens it holds. The confinement
that matters stays at the token; the relaxation is a minor DNS-visibility leak.

### D5: Single endpoint, in-band capability-token demux (replaces port-mux)

SSH has no SNI, and git over SSH transmits no upstream hostname in-band: the exec
request carries the repository path, not the host (the `host=` virtual-host
parameter exists only in the git daemon protocol, not over SSH). The front
therefore does not read the target from the stream. It assigns it.

The selector is a high-entropy random **capability token encoding (step, peer)**,
issued per step per peer for the lane run, injected as `SetEnv STRIKE_PEER=<token>`
in the system-wide ssh_config `Host` block for that peer. The front reads the env
channel request, looks the token up in its per-run dispatch table to recover
(step, peer), routes to that step's capsule context, and dials that peer's
upstream. A connection presenting an unknown or absent token is **refused**
(fail-closed; there is no ambient or default peer, and no default step). The step
is *not* recoverable from the network (the spike result: source identity collapses
under pasta); it lives only in the token.

The token is a routing capability, not a trust anchor (ADR-037 D2 corollary).
Trust is the upstream anchor validation of D3; the token only selects which
(step, peer) a connection is routed to, and every token maps to a *declared* peer
of a *declared* step, so a container presenting a different valid token reaches
another declared peer, never an undeclared one.

What the token adds over the port-mux it replaces is that it is **not trivially
circumventable** and **not enumerable**: a port is an enumerable identifier, and
on a shared endpoint a hostile container could scan ports and reach every peer
that endpoint knows, including other steps' peers. A high-entropy token is a
non-enumerable bearer capability, per-step ephemeral, and the front rejects any
unknown token, so on the single shared endpoint each container reaches exactly
the (step, peer) pairs whose tokens it was given, with no guessing. Cross-step
isolation of the tokens themselves rests on inter-container isolation, which is
Layer E (engine-enforced, ADR-037 D4): if that isolation breaks and a container
steals another step's token, the front still validates the upstream peer identity
truthfully (no false positive on the verified claim), and only the step
*attribution* is corrupted -- exactly the graceful degradation ADR-037 D2's
"selection is not trust" predicts.

A single ephemeral front host key serves all connections. There is no
chicken-and-egg with per-step keys: the near-side key exchange completes before
the token is read, and the upstream dial is deferred until the allowlisted
exec/subsystem request arrives, by which point the token has selected (step, peer).

This drops the per-peer SSH host-port allocation entirely (the `SSH` blocks in the
capsule allocator's `HostPorts`, the `containerPorts` parameter, and the per-`Host`
`Port` directive). The control plane exposes a single inbound endpoint per lane
run, not a port range.

The demux rides in the injected ssh_config. The migration from
`GIT_SSH_COMMAND -F <file>` to system-wide ssh_config injection (the deferred
ADR-033 follow-up, and the decided direction: tools that cannot use the
system-configured transport are unsupported) does not affect it: `SetEnv` is an
ssh_config directive that lives in the system-wide `Host` blocks as readily as in
a `-F` file. The policy guarantees a `SetEnv`-honoring client for supported tools;
a libssh2-only client that ignores it is unsupported by the same rule that
excludes own-CA tools.

### D6: SSH framing terminated, payload relayed

The front terminates SSH framing in full (transport, userauth, channel requests)
so the exec or subsystem request is visible and checkable against the D1
allowlist, and so the upstream identity is captured on the real session path. The
channel *payload* (the git pack stream, the sftp/rsync data) is relayed opaquely
between the terminated near-side channel and the front's upstream channel; the
front does not parse protocol semantics beyond what D7 records and what D1
allowlisting requires. "Terminate the framing, relay the payload." This is what
makes D1 enforceable and D7 session-bound, and it is why a dumb L4 front is
impossible (D2).

### D7: Notarization scope and provenance discipline

strike notarizes only mediated traffic. Traffic a host allows around the front is
a false negative, not a false positive: strike never signs a connection it did not
observe. Per ADR-037 D2 the attestation is **self-describing about scope** (it
records the peers strike mediated; it does not assert this was the exhaustive
egress) and **about provenance** (no record mixes trust levels unmarked).

Per mediated SSH connection, when the per-peer connection records land (they are
Phase-2, currently unbuilt), the record splits per ADR-037's no-mixing rule:

- The **observed** part (Layer V): the upstream server host-key fingerprint
  validated against the declared anchor, negotiated algorithms, the allowlisted
  command. Session-bound, because the front is the actual upstream client.
- The **engine-asserted** part (Layer E): the attribution of the connection to a
  specific step. This rests on the token, whose per-step secrecy rests on
  inter-container isolation (Layer E). It is recorded as engine-asserted, not as a
  verified fact, and must be structurally distinguishable from the observed part.

Content integrity for git is the commit digest pin (ADR-011, Layer V), not the
mediation.

Optionally (see open points), the repository path from the exec request may be
recorded and restricted against a declared per-peer path allowlist. This is the
one genuinely protocol-specific lever the termination buys; step+peer
disambiguation (D5) does not use it.

## Consequences

- "Peers are declared" becomes structurally enforced for SSH at the protocol
  level, not just the egress level: an SSH step reaches only its declared peers,
  and within a peer only the allowlisted protocol.
- A step container with SSH peers has no agent socket, no real peer `known_hosts`,
  trusts a single ephemeral front identity, and runs no upstream command except
  the allowlisted one.
- The control plane gains, for the first time, an inbound listener (the front).
  This interacts with ADR-037 D5.1: exposing the plane is the reason to
  externalize the signing key rather than hold it on a network-reachable process.
  The ordering (externalize, then expose) is a cross-ADR dependency.
- The capsule stops owning its container-facing interface and its crypto endpoint
  (both lift to the front) and keeps its per-step policy; the allocator loses the
  per-step SSH port blocks and the `containerPorts` parameter.
- strike now contains an SSH server and an SSH client (`golang.org/x/crypto/ssh`,
  both sides), which must clear the dependency policy (justification, govulncheck,
  license, transitive count). The trade is deliberate: less capability (no generic
  SSH, no shell, no in-container oracle) for bounded code. For a tool whose purpose
  is attack-surface reduction this is worth it, but the cost is recorded here, not
  hidden.
- The trust boundary sharpens: the engine becomes wholly Layer E, and the control
  plane provides no independent check on inter-container isolation. A break of
  that isolation corrupts step *attribution* only, never the verified peer-identity
  claims (D5, ADR-037 D2). SECURITY.md must say so.
- Mixed HTTPS+SSH steps and the unified-mediation intent of ADR-033 are preserved;
  HTTPS and DoT ride the same front, with HTTPS demuxed by SNI and DoT resolving
  lane-permissively (D4).

## What is not supported

Failing closed with a clear diagnostic before any container starts:

- Generic SSH: interactive shells, arbitrary remote commands, SSH port forwarding,
  agent forwarding into the container.
- Container-held private keys of any kind (ADR-007 unchanged).
- Tools that bypass the system-configured SSH transport, or that do not honor the
  injected ssh_config (e.g. libssh2-only clients that ignore `SetEnv`).
- Per the HTTPS rules (ADR-028): tools with hardcoded CA stores or their own
  client identity.

## Rejected alternatives

- **Generic SSH relay with handshake-only notarization.** strike stays a TCP relay
  and parses the cleartext key exchange to record the server host key. Rejected:
  past the key exchange everything is encrypted, so this can neither see nor
  restrict the command, cannot eliminate the in-container oracle, and leaves the
  agent reachable. It addresses none of Context problems 1-3.
- **HTTP-git bridge.** The container speaks git-over-HTTPS to the front, which
  speaks SSH upstream. Rejected: avoids an sshd but requires a smart-HTTP-git
  server implementation (a substantial dependency) and is git-specific;
  scp/sftp/rsync do not fit, whereas D1's command allowlist generalizes.
- **Network-identity (source IP) step demux.** Route by the container's source
  address instead of a token. Rejected on the spike result: rootless pasta
  collapses all container egress to the host address at the netns boundary, so no
  per-container source identity reaches a control-plane front. `--outbound` /
  `--address` do not survive the boundary NAT, and non-NAT routed egress needs
  `CAP_NET_ADMIN` (unavailable rootless).
- **Per-peer IP demux (single port, many IPs).** Encode the peer in the
  destination IP and recover it via the connection's local address or
  `SO_ORIGINAL_DST`. Rejected for the remote engine: it carries the same or a
  sharper problem than port-mux, needing either multiple routable IPs across the
  boundary (a wider inbound surface) or an engine-side NAT/forwarder (an engine-
  side component, excluded by the control-plane-only decision, and rootless-NAT-
  limited).
- **Sidecar / engine-embedded front.** Run the front (or strike entirely) as a
  container on the engine. Rejected: it moves Layer-V production (peer-identity
  observation, and with an embedded key the signing) onto the untrusted engine,
  forbidden by ADR-037 D5 absent compensation (KMS/keyless or TEE attestation) or
  an explicit scope widening. The control-plane front keeps the engine wholly
  untrusted.
- **Per-step front / per-step capsule process.** A separate listener or process
  per step. Rejected as the default: it reintroduces a port range (per-step
  listeners) or needs an internal plaintext-proxy hop (a terminated SSH channel
  cannot be fd-passed), for fault/resource isolation that per-connection recovery
  and per-step budgets provide in-process. The in-process per-step context (D2)
  keeps this reversible if operational evidence later demands OS-level isolation.

## Open points for revision

- **Repo-path granularity.** Whether `#SSHPeer` (or a git-specific peer variant)
  gains a declarable allowed-path field, enforced and recorded per D7, or whether
  the path is recorded but unrestricted, or deferred.
- **Upstream credential source sequencing.** Host ssh-agent in the front (step 1)
  to KMS/keyless (step 2) per ADR-037 D5.1. Decoupled from the container-facing
  design but worth sequencing explicitly against the inbound-exposure ordering.
- **Front inbound-trust mechanism.** Server-authenticated TLS for the
  container-to-front hop plus the token as a bearer credential (no container-held
  key, so not mutual at that hop); distinct from any mTLS on a non-container-
  terminated engine-to-control-plane transport. To be specified separately.
- **Wiring verification.** The DNS-redirect plus single-endpoint behaviour, and
  the rootless netavark/pasta path that realizes "no route except via the front",
  verified on the target Podman version. The model holds; the wiring is
  version-dependent.
- **Client-landscape verification.** `SetEnv` support (OpenSSH 7.8+) against the
  real build-image SSH clients, consistent with the unsupported-tools policy.

## Principles

- No shell (generic SSH and shells are structurally unreachable; the allowlist is
  the entire surface).
- Peers are declared (now protocol-mediated and command-restricted, not relayed).
- Identity is asymmetric (server identity validated controller-side against the
  declared anchor; client identity held by an authority in the control plane; the
  container holds neither).
- Runtime is attested (session-bound upstream identity capture; scope recorded as
  mediated-not-exhaustive; step attribution recorded as engine-asserted, ADR-037).
- External references are digest-pinned (git content integrity is the commit pin;
  the mediation does not claim it).
- Code is liability (one front plus a reused per-step policy context; the added
  sshd surface is a deliberate, recorded capability-for-code trade; no per-step
  processes, no per-field trust tags).
- Enforcement is structural, not discretionary (the command allowlist, the
  fail-closed token, the topology egress; no per-peer opt-out, no ambient default).
