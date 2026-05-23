# ADR-028: Step-Container Egress Mediation

## Status

Accepted. Companion to [ADR-022](ADR-022-network-opt-in-as-peer-list.md);
fulfills the deferred enforcement promise (the "Phase 2 gets its own
ADR when a concrete enforcement story is needed" sentence). Refines
but does not supersede [ADR-005](ADR-005-per-step-security-profile.md),
[ADR-007](ADR-007-asymmetric-identity.md),
[ADR-022](ADR-022-network-opt-in-as-peer-list.md),
[ADR-024](ADR-024-ssh-known-hosts.md),
[ADR-025](ADR-025-ssh-agent-proxy.md).

> **Completed by [ADR-033](ADR-033-ssh-peer-egress-and-unified-mediation.md):**
> this architecture is realized by the per-step NetworkCapsule. The
> concrete egress mechanism is pasta `--splice-only` with per-unit port
> forwards (ADR-031, ADR-033), not the DNAT-redirect model sketched
> under Component 3, which was left "deferred to engineering" here.
> ADR-033 also supersedes the interim "HTTPS-without-SSH only" dispatch
> (ROADMAP-ADR-028.md D26): every step container runs under a capsule,
> SSH peers are mediated by per-peer raw-TCP forwards, and the
> `--network=none`/`--network=bridge` modes are removed.

## Context

[ADR-022](ADR-022-network-opt-in-as-peer-list.md) replaced the
single-bit `network: true` field with a typed peer list. It established
that any step using the network must enumerate its peers together with
the appropriate trust anchor (cert fingerprint or CA bundle for HTTPS,
known_hosts for SSH, image digest for OCI). It then explicitly deferred
concrete per-peer enforcement: the peer list flows into the deploy
attestation, the kernel sees only the bridge/none switch, and per-peer
enforcement ("`extra_hosts` injection, CA-bundle bind mounts,
ssh-agent socket forwarding, egress filtering") was left for a
follow-up ADR when a concrete enforcement story was needed.

This is that ADR.

### Threat model: step containers

A step container is potentially:

- A compromised dependency (a malicious package pulled by `npm install`,
  `pip install`, `cargo fetch`, `go get`)
- A malicious binary (a forged tool version, a backdoored build helper)
- LLM-generated code carrying prompt-injection-controlled behaviour
- Otherwise-trusted code with a remote-code-execution vulnerability
  triggered by hostile input

Within this threat model, the step container must not be able to:

- Resolve DNS names not on the declared peers list
- Open TCP connections to hosts not on the declared peers list
- Send UDP traffic (outside controlled DNS queries to strike's resolver)
- Send ICMP, open raw sockets, or use other IP protocols
- Hold cryptographic identity material that strike cannot mediate
- Choose its own trust authority for any connection strike attests
- Exfiltrate via any side channel that is not blocked at the kernel
  or network-namespace boundary

The step container must be able to:

- Resolve DNS for declared peer FQDNs
- Open TCP connections to declared peers (HTTPS, SSH, OCI registry)
  through strike's controller-side mediators
- Use Client identity (SSH key, mTLS client cert) held at the
  controller, via the asymmetric-identity mechanisms of
  [ADR-007](ADR-007-asymmetric-identity.md)

### Threat model: controller-side network dependencies

The step-container threat model handles untrusted code inside the
container. A complete enforcement story must also address the
controller's own network dependencies, because the peer-validation
mechanism builds on FQDN-to-IP mappings that come from somewhere.
If that "somewhere" is uncontrolled, the entire peer-trust chain
inherits whatever the resolver felt like saying.

Concretely, an uncontrolled DNS path lets an attacker:

- Hijack a CI runner's local network DNS so that strike's resolution
  of a declared peer FQDN returns an attacker-controlled IP
- Manipulate BGP-level routing of a public DNS service so that the
  controller's recursive resolution against root servers is
  redirected
- Profile which hosts strike resolves, even when the connection
  itself ultimately fails TLS verification (side-channel
  information about what builds are running)

Most existing build tools treat DNS resolution as implicit
infrastructure trust: whatever `/etc/resolv.conf` says is what they
use, and the result is unrecorded. This is the same blind spot
that originally motivated peer trust anchors at the TLS layer. The
DNS layer is structurally analogous and deserves the same treatment.

### Why advisory mechanisms are insufficient

`HTTP_PROXY` / `HTTPS_PROXY` environment variables, `/etc/resolv.conf`
entries, and application-level trust pinning are all *advisory*. A
statically-linked binary that bypasses libc's environment-handling, a
malicious package that intentionally ignores proxy variables, a tool
that simply does not know about `HTTP_PROXY` -- any of these breaks
out of an advisory proxy. The first action of a serious adversary in
this position is exactly that bypass.

For the threat model above, the enforcement boundary must be at the
network-namespace level, where the container process literally cannot
reach what is not authorised, regardless of in-container code.

### On the legitimacy of TLS termination in this context

The architecture below performs TLS termination on traffic between the
step container and its declared peers. TLS termination has a deservedly
poor reputation in contexts where privacy and informational self-
determination of individuals are at stake: an ISP intercepting user
traffic, a state actor running mass surveillance, an employer doing
opaque inspection of employee communications. In all of these, an
*unrelated third party* intercepts the traffic of two parties that
willingly intended to communicate directly.

The strike model contains no such third party. The lane operator
defines the lane, configures the peers list, executes the step
container, and supplies the trust anchors. The "man in the middle" is
the operator's own controller process, running code the operator
specified, inspecting traffic of build steps the operator orchestrated,
to provide attestations the operator wants. There are no individuals
whose communications are being monitored; there is no asymmetric
power relationship. The pattern here is closer to log inspection,
code review, or any other form of an operator overseeing their own
build pipeline than it is to network interception in the privacy
sense.

The "no-MITM" position carries weight where its premises hold. Those
premises do not hold here. Conflating the two contexts would force a
choice between strong supply-chain attestation and a misapplied
privacy principle. We choose attestation.

### Why per-peer escape hatches are structurally inadequate

A natural variant of this architecture is "default to mediation,
allow per-peer opt-out for cases where the mediation does not fit."
The opt-outs typically named are (a) tools with hardcoded CA stores
that cannot trust the operator's ephemeral CA, and (b) protocols
where the container holds its own client identity (mTLS in
container, custom auth protocols).

Both opt-outs are abuse cases on closer inspection:

- A tool with a hardcoded CA store is one that has selected its own
  trust authority independent of any operator configuration. This is
  the property an attacker would design *for*: write a tool that
  ignores operator trust, get a lane to declare it incompatible with
  the mediator, operate outside the attested trust domain. Allowing
  per-peer opt-out for these tools converts a tool-design choice
  into a sanctioned bypass.
- A container holding mTLS client identity means private key material
  resides in container memory. This is exactly the asymmetric-identity
  violation [ADR-007](ADR-007-asymmetric-identity.md) was written to
  prevent. The container can dump, exfiltrate, or misuse the key in
  ways strike cannot detect or attest. The right answer is the same
  pattern strike already uses for SSH: keep the client identity at
  the controller, mediate the upstream handshake on the step's
  behalf.

The set of legitimate uses of per-peer opt-out is empty. The
architecture therefore has no per-peer opt-out.

### Why advisory peer enforcement is structurally inadequate

Without termination, attestation can record at most what the step
container *claimed* via TLS SNI. With TLS 1.3 (mandated by this
ADR's transport primitive), even SNI may be encrypted (ECH), erasing
the last hook for in-flight inspection. Termination is the only
mechanism that lets strike record what the build step actually
connected to and what cryptographic identity that peer presented.

This matters because the central promise of an attested supply-chain
tool is not "this build claimed X" but "this build did X, and here is
the verifiable record." A passthrough-only architecture would weaken
that promise.

## Decision

A three-component egress mediation subsystem. All step-container
egress passes through strike-controller-owned mediators. The peers
list in the lane definition is the single ground truth for both
runtime enforcement and deploy attestation. DNS resolution is
treated as a peer-trust problem on equal footing with any other TLS
endpoint strike depends on; the lane must declare its DoT resolver
explicitly with a trust anchor.

Two protocol-level mediation patterns are supported: TLS mediation
for TLS-based protocols, and SSH mediation for SSH. Both share the
identity-asymmetry principle: controller holds client identity, the
declared trust anchor governs server identity, the egress filter
enforces destination restriction. No third pattern exists; protocols
that cannot be expressed in either pattern do not run.

### Component 1: Controller-side DNS resolver

A DNS resolver process inside the strike controller. The step
container's network namespace is configured (Component 3) so that
all UDP/53 and TCP/53 traffic is redirected to this resolver.

For each query:

- If the queried FQDN matches an entry on the step's peers list:
  resolve via the lane's declared DoT resolver (see below), record
  the result, return it to the container. The resolved IP becomes
  part of the attestation: "FQDN x.y.z resolved to IP a.b.c.d at
  timestamp T."
- If the queried FQDN does not match the peers list: return NXDOMAIN.
  This is not a statement about whether the name exists in the world;
  it is a declared response meaning "this name is not authorised for
  this lane step."

This eliminates direct command-and-control over DNS. A compromised
package that attempts to phone home to an attacker-controlled host,
to tunnel exfiltration via DNS, or to hardcode a C2 hostname, finds
the resolver returning nothing. The container has no path to reach
unauthorised DNS upstreams because Component 3 redirects all DNS
traffic to this resolver.

#### DoT resolver as declared peer

The lane definition must declare exactly one DNS resolver, with a
trust anchor, using the same `#FingerprintTrust | #CABundleTrust`
vocabulary as HTTPS peers. The resolver is a trusted TLS endpoint
in exactly the same sense as any other peer: same trust-anchor
mechanism, same identity-capture pattern, same attestation surface.

The resolver declaration is mandatory. A lane without a declared
resolver does not execute -- fail fast, fail hard. There is no
implicit fallback to system DNS (`/etc/resolv.conf` is ignored),
no recursive resolution against root servers (no recursive path
exists in strike's code), and no plaintext DNS at any layer. The
controller has exactly one DNS upstream per lane run, and that
upstream is TLS-verified against the declared anchor.

The resolver's TLS identity is captured on the first DoT handshake
of a lane run and flows into the deploy attestation. Replacing the
resolver across runs requires updating the lane definition; the
attestation records which resolver provided each FQDN-to-IP
resolution.

The schema placement of the resolver declaration (lane-level field
vs. discriminator-variant of `#Peer`) is a schema-design decision
deferred to implementation; what is committed here is that the
trust-anchor vocabulary, attestation capture pattern, and
mandatoriness are identical to those of any other declared TLS peer.

User-facing documentation accompanying this work must demonstrate
viability with three major public DoT services (Cloudflare 1.1.1.1,
Quad9 9.9.9.9, Google Public DNS 8.8.8.8) and at least one
self-hosted resolver (IPFire as the open-source example). The
self-hosted example carries weight: the architecture must not
implicitly lock operators into a small set of public DNS providers.

### Component 2: Controller-side mediation

A mediation process inside the strike controller. The step
container's network namespace is configured (Component 3) so that
all TCP traffic is redirected to this mediator. Two patterns exist;
the pattern is determined by the declared peer type, not by lane
configuration.

#### TLS mediation (HTTPS peers, TLS-based protocols)

The mediator terminates TLS from the container side, presenting a
server certificate signed by an *ephemeral per-lane-run CA* whose
public certificate is mounted into every step container as a trusted
CA. The mediator then opens its own TLS connection upstream to the
declared peer, applying the verification specified by the peer's
trust anchor:

- `cert_fingerprint`: the upstream server certificate's SHA-256 must
  equal the declared value
- `ca_bundle`: the upstream server certificate must validate against
  the declared CA bundle path

If verification fails, the upstream connection is not established;
the container-side connection is closed; the failure is recorded in
the attestation.

If verification succeeds, the mediator captures the upstream TLS
identity (certificate chain, fingerprint, TLS version, cipher suite,
peer hostname) and threads the connection through. The captured
identity flows into the deploy attestation alongside the declared
peer.

TLS mediation is the only path for TLS-based protocols. There is no
passthrough mode. Tools that cannot trust the ephemeral CA do not
run; tools holding their own client identity in the container do
not run (see "What is not supported", below).

#### SSH mediation

SSH is not TLS, but the same identity-asymmetry principle applies.
The mediation pattern for SSH consists of three pieces that already
exist in strike, now bound together under the same architectural
commitment as TLS mediation:

- **Client identity at the controller** via the ssh-agent-proxy
  pattern ([ADR-025](ADR-025-ssh-agent-proxy.md)). The container
  speaks the SSH protocol to its upstream peer, but the
  authentication signature is computed by strike's controller-held
  agent. The container never has the private key.
- **Server identity verified against declared trust anchor** via
  the known_hosts mount pattern
  ([ADR-024](ADR-024-ssh-known-hosts.md)). The mediator TCP-forwards
  the SSH connection; the container's SSH client validates the
  server's host key against the mounted known_hosts file derived
  from the peer declaration.
- **TCP egress restricted to declared SSH peers** via Component 3.
  An SSH connection attempt to an undeclared host is dropped at the
  network-namespace level before the SSH protocol exchange begins.

This is the SSH-shaped analog of TLS mediation: client identity at
controller, server identity against declared anchor, egress
restricted. The asymmetry is that for TLS the mediator itself
performs server-identity verification (because it terminates),
while for SSH the container's SSH client performs verification
against a strike-mounted file. The trust anchor in the lane
declaration is the same kind of statement in both cases; the
mechanical execution differs because the protocols differ.

#### What is not supported

The mediation surface is intentionally narrow. The following
patterns are not supported and lanes invoking them do not run:

- **Plain HTTP** to declared peers. No TLS means no peer identity
  to verify against a trust anchor; the attestation gap is
  unbounded. Lanes that need an HTTP-only service must wrap it in
  a TLS-terminating frontend.
- **Tools with hardcoded CA stores** that cannot trust the
  ephemeral per-lane-run CA. The tool has selected its own trust
  authority; allowing it through would let it operate outside the
  attested trust domain.
- **Container-held mTLS client identity**. Any client identity
  material the proxy mediates must be at the controller, as a
  typed Secret consumed at upstream handshake time. Container-held
  keys violate ADR-007 identity asymmetry.
- **Non-TLS, non-SSH protocols** not explicitly mediated. Adding
  a new protocol means adding controller-side mediation code with
  the same identity-asymmetry properties. It is not a per-peer
  lane-author choice. Lanes that need an unsupported protocol
  cannot opt out of mediation; either the protocol gets a proper
  strike-controller mediator, or the lane does not run.
- **Raw TCP allowlists**. There is no "this peer talks plain TCP,
  just let it through" mode. Plain TCP carries no identity that
  strike can attest, and a permissive raw-TCP path would be the
  same kind of escape hatch as plain HTTP.

This list is intentionally restrictive. Every entry corresponds to
a class of bypass that an attacker would choose given the choice.
The architecture refuses to give the choice.

### Component 3: Network-namespace egress filter

The step container's network namespace is configured before the
container process starts. The filter rules:

- All outbound traffic from the container network namespace is
  DROP by default
- UDP destination port 53 is DNAT-redirected to strike's DNS resolver
  (Component 1)
- All TCP, regardless of destination port or address, is DNAT-redirected
  to strike's mediator (Component 2)
- Other IP protocols (ICMP, IGMP, etc.) and raw sockets are DROP

The filter is installed by the OCI runtime as part of network-namespace
setup, before the container's main process starts. The container
process runs with `cap-drop=ALL` per
[ADR-005](ADR-005-per-step-security-profile.md), and therefore cannot
modify these rules from within the namespace.

Concrete implementation paths in the rootless setting are deferred
to engineering: `netavark` plus custom firewall config, a custom CNI
plugin installing nftables rules at namespace creation, or `pasta`
configured as the network backend with restrictive port forwarding.
The architectural commitment is that enforcement is at the
network-namespace boundary, not at the container application layer.

### Peers list as ground truth

The same trust-anchor mechanism serves four roles:

- **Enforcement spec for step traffic.** DNS resolver, mediator,
  and egress filter all consume the same per-step peer declarations.
  There is no separate "enforcement config" to drift from the
  declaration, and no per-peer mode field that could be set
  inconsistently.
- **Enforcement spec for controller's own DNS.** The declared DoT
  resolver is the only DNS path strike uses. Same trust-anchor
  vocabulary.
- **Attestation declaration.** What the lane author signed up for,
  in both step-peer and resolver dimensions.
- **Attestation runtime record.** What actually happened, captured
  by the resolver and mediator: FQDN resolved to IP via resolver R
  with identity I, TCP connection established to peer P, TLS
  handshake produced cert chain X with fingerprint Y at timestamp T,
  or SSH connection established to declared SSH peer with the
  known_hosts entry matching server key K.

The strengthening is that the gap between "declared" and "enforced"
is closed structurally: the mediator and resolver are the only paths
the controller and container have, and both obey the declaration
without per-peer escape hatches.

### Attestation surface

The deploy attestation gains per-lane-run and per-peer runtime
records:

- `dns_resolver`: identity of the DoT resolver used by this lane run
  (host, port, captured cert chain, fingerprint, TLS version, cipher
  suite). Captured once, on the first DoT handshake; applies to all
  resolutions in this run.
- Per declared peer:
  - `resolved_to`: IP addresses the FQDN resolved to during this run
  - `connections`: per upstream connection
    - timestamp
    - destination IP and port
    - For TLS peers: cert chain, fingerprint, TLS version, cipher
      suite (captured by the mediator)
    - For SSH peers: connection metadata; the validated host key is
      already in the lane's known_hosts entry, so the attestation
      simply confirms the connection succeeded against that entry

The exact schema lives in a follow-up ADR or the next iteration of
the attestation schema; the architectural commitment here is that
this material exists and is signed under the DSSE envelope
([ADR-013](ADR-013-dsse-envelope-and-rekor.md)).

## Consequences

### Attestation becomes structurally verifiable end-to-end

The chain "lane declared resolver R with anchor A_r -> lane defined
peer P with anchor A_p -> step ran -> resolver R returned IP I for
peer P -> step's HTTPS calls reached IP I -> upstream certificate
matched A_p" is captured end-to-end, signed, and submitted to Rekor.
A verifier replaying this chain can determine what the build actually
did with respect to declared trust anchors, including which DNS
authority mediated the resolution. This is the central supply-chain
attestation guarantee, extended one layer deeper than is conventional.

### Closing the DNS-resolver blind spot

Most existing build tools treat DNS as implicit infrastructure trust:
whatever the host resolver says is what they use, and the resolution
is unrecorded. Supply-chain attestation work in the broader ecosystem
similarly tends to start at TLS and treat the DNS layer as someone
else's problem. By requiring an explicit DoT resolver with a declared
trust anchor and runtime-attested identity, strike closes that blind
spot. This is a positive differentiator and aligns the DNS layer with
the same first-principles treatment the rest of the trust graph
receives.

### Universal mediation, no escape hatches

The architecture commits to two mediation patterns (TLS, SSH) and
refuses everything else. There is no per-peer opt-out, no
"compatibility mode" that bypasses the mediator, no raw-TCP
allowlist, no plain-HTTP path. Adding support for a new protocol
means adding controller-side mediation code with the same
identity-asymmetry properties as the existing patterns -- a
controller-source change, not a lane-configuration change.

This is restrictive. The set of legitimately supported lanes is
narrower than under a permissive design. It is also the property
that makes the attestation chain verifiable end-to-end: there is no
gap where strike says "this peer's behaviour is unattested." Every
connection a step makes has a controller-mediated counterpart with
a declared trust anchor and a captured runtime identity. This is the
guarantee that distinguishes strike from build tools that ship a
permissive default with hardening as opt-in.

### One TLS verification implementation, multiple consumers

The TLS verification primitive (`internal/transport`, Phase 1) is
consumed by:

- Component 1's DoT calls to the declared resolver
- Component 2's TLS-mediation upstream handshakes
- Strike's own direct calls (audit-sink transport per
  [ADR-014](ADR-014-audit-pipeline.md), Rekor calls, `strike verify`)

This is "code is liability" applied at the architectural level: one
implementation of a single security-critical primitive, with multiple
declarative consumers, rather than per-consumer ad-hoc TLS handling.
Component 1 becomes the first production consumer of the transport
primitive *within* the same release that implements the primitive,
which sharpens Phase 1 acceptance: if the primitive is not solid,
DoT resolution fails visibly on the first lane.

### Strong rootless enforcement is possible but engineering-heavy

The namespace-level egress filter does not require root on the host;
it requires `CAP_NET_ADMIN` within the user namespace owning the
container's network namespace, which the OCI runtime has at
namespace-setup time. Three concrete paths are viable (netavark,
custom CNI, pasta); selection between them is engineering, not
architecture.

The container process, post-cap-drop, cannot modify the filter,
cannot escape the namespace, and cannot reach outside what the
filter permits. This is the enforcement-strong end of the spectrum
ADR-022 left open.

### Tool compatibility is a hard requirement, not a soft trade-off

Container tools must trust the ephemeral per-run CA (for TLS) and
must not hold their own client identity (for all protocols). For
the vast majority of build tooling (curl, wget, git, npm, pip,
cargo, go), the first condition is satisfied by mounting the CA's
public certificate into the container's system CA store
(`/etc/ssl/certs/ca-certificates.crt` on Debian/Alpine bases,
analogous paths elsewhere). The second is satisfied by the
ssh-agent-proxy pattern for SSH; for HTTPS clients, mTLS support
through the mediator (with controller-held client identity) is a
Phase 3 deliverable.

Tools that fail these conditions -- hardcoded CA stores,
container-embedded private keys -- are not supported. This is the
intended behaviour, not a regression to be patched around. Lanes
that attempt to use such tools fail with a clear diagnostic at
validation time, before any container starts.

### Operational requirement: a reachable DoT resolver

Every lane run requires a reachable DoT resolver. This is a hard
operational dependency, intentionally not softened with fallback to
system DNS. Operators choose between public DoT services
(Cloudflare, Quad9, Google Public DNS), self-hosted resolvers
(IPFire, Unbound with stunnel, etc.), or contractually-bound
enterprise DNS infrastructure. The trade-off favours a closed trust
chain over operational flexibility; lanes with sensitive resolution
constraints can declare a self-hosted resolver.

### ADR-022's "Phase 1 is declaratory" wording becomes obsolete on
implementation

When this ADR is implemented, the Phase 1 / Phase 2 framing in
ADR-022 no longer describes the present. ADR-022 will be updated to
reflect the implemented state at that time. Until implementation
lands, ADR-022's current wording remains accurate (it describes
today's reality) and is left in place.

### Performance is annotated, not blocking

Proxying all TCP traffic through the controller adds a hop. For
typical CI workloads (npm install, git clone, container pull) the
upstream is the bottleneck, not the mediator; the overhead is small
relative to total step time. For latency-sensitive workloads, the
overhead is observable. The trade-off favours attestation strength
over raw throughput; lanes that need maximum throughput can declare
no peers (network=none) and stay entirely offline.

### OCI behaviour clarifies

OCI registry calls split by initiator. Controller-initiated OCI
operations (base image pulls, output pushes) use the
`internal/transport` primitive directly without going through the
container egress mediation -- they are not container traffic. If a
step container itself invokes OCI tooling (rare, but conceivable for
build images that publish artifacts during the build), that traffic
flows through Component 2's TLS mediation pattern like any other
HTTPS peer.

## Phase boundaries

**Phase 1** (in progress): `internal/transport` TLS verification
primitive. Consumed by Component 1's DoT calls, Component 2's
TLS-mediation upstream handshakes, and direct controller calls.
Phase 1 is not gated on the rest of this ADR landing; it has
independent value for audit-sink (ADR-014) and `strike verify`. The
DoT path makes Component 1 the first in-process consumer, which
makes Phase 1 acceptance directly testable against real-world DoT
services.

**Phase 2** (this ADR): the three components together, integrated
with the lane schema's peers list and the lane-level resolver
declaration. Order within Phase 2: DoT resolver declaration
mechanics (schema + transport call), DNS-resolver component with
allowlist logic, TLS mediation, SSH mediation integration (binding
together the existing ssh-agent-proxy and known_hosts patterns
under the same architectural roof), egress filter integration with
the chosen rootless backend, attestation-surface extension.

**Phase 3** (separate ADRs): mTLS via controller-held Client-Cert
(typed Secret kind, mediator authenticates on behalf of step),
audit-sink integration with full transport stack, deeper rootless
backend choice ratification, additional protocol mediators if and
when concrete need arises.

## Open follow-ups

Named here without resolution; each gets its own decision when the
implementation reaches it:

- **Rootless network backend choice**: netavark vs. custom CNI vs.
  pasta. The architectural commitment is the egress-filter
  capability; the choice between backends is an engineering decision
  driven by maturity, test coverage, and host-OS compatibility.
- **Resolver schema placement**: whether the lane's DoT resolver is
  declared as a top-level `#DNSResolver` field, as a fourth
  discriminator-variant of `#Peer`, or under `#LaneDefaults`. The
  trust-anchor types and attestation pattern are committed here;
  the schema topology is open.
- **Ephemeral CA management**: per-lane-run vs. per-strike-process
  CA lifetime; CA-private-key handling (in memory only, never on
  disk); CA-public-cert mount mechanics.
- **mTLS specifics**: Client certificates as a typed Secret kind,
  consumed by the mediator at upstream-handshake time. Requires a
  small schema extension and is connected to ADR-007's identity
  asymmetry.
- **Enforcement test methodology**: how to prove, in CI, that a
  container cannot reach a non-declared host, that the DoT resolver
  path is the only DNS path used, and that an attempt to use an
  unsupported pattern (plain HTTP, hardcoded-CA tool) fails at
  validation time. Likely a dedicated integration-test category
  that runs deliberately-adversarial steps and asserts on
  attestation contents and validation behaviour.
- **ADR-022 update**: once Phase 2 is implemented, ADR-022's "Phase
  1 is declaratory" wording is replaced with the implemented
  reality. Until then, ADR-022 stays as is.
- **Documentation deliverable**: user-facing documentation must
  cover four resolver configurations -- Cloudflare 1.1.1.1, Quad9
  9.9.9.9, Google Public DNS 8.8.8.8, and IPFire as a self-hosted
  example -- with current trust anchors and minimal viable lane
  snippets for each. Tracking item against the Phase 2
  implementation.

## Principles

- **No root.** Egress mediation works in rootless podman; no
  privileged helper, no host-side root setup.
- **Peers are declared.** The peers list is the single source of
  truth for both enforcement and attestation; there is no parallel
  enforcement config that can drift, and no per-peer escape hatch
  that could be set to bypass mediation. The DoT resolver is on
  equal footing with any other peer: same trust-anchor vocabulary,
  same attestation capture, same mandatoriness.
- **Identity is asymmetric.** Client identity stays at the
  controller; server identity is governed by the declared trust
  anchor. Both TLS mediation and SSH mediation enforce this; no
  pattern is supported that would allow container-held client
  identity material.
- **Universal mediation.** Every container outbound connection
  passes through a strike-mediated path with declared trust anchors.
  There is no per-peer opt-out, no raw-TCP allowlist, no plain-HTTP
  exception, no compatibility mode. New protocols join via
  controller-side mediator code, not via lane configuration.
- **Runtime is attested.** TLS identities, resolved IPs, resolver
  identity, and connection metadata are captured and signed;
  attestation records what happened, not what was intended.
- **Code is liability.** One TLS verification implementation
  (`internal/transport`); multiple consumers (resolver, mediator,
  audit, verify). No per-consumer ad-hoc TLS code.
