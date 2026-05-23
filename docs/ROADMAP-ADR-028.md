# Implementation Roadmap: ADR-028 (Step-Container Egress Mediation)

**Purpose.** This document is the context-reload anchor for
implementation work on ADR-028. It captures the architectural target,
the ratified design decisions, the PR sequence with current status,
and the conventions that govern instruction-writing for this track.
A Claude Code session that loads this document plus the relevant
ADRs has the complete big picture for continuing the work without
needing to reconstruct context from chat history.

This document is updated as PRs land, decisions are added, or the
scope changes.

## Architectural target

The architecture is specified in
[ADR-028](ADR-028-step-container-egress-mediation.md). One-paragraph
summary for orientation:

A three-component egress-mediation subsystem in the strike controller
(DNS resolver with FQDN allowlist; TCP mediator with TLS termination
plus the SSH-specific mediation pattern; network-namespace egress
filter) restricts every step-container outbound connection to
controller-mediated paths with declared trust anchors. The lane's
peer list and a mandatory DNS-over-TLS resolver declaration are the
single ground truth for both runtime enforcement and signed deploy
attestation. Two mediation patterns are supported (TLS, SSH); no
per-peer escape hatches exist. The architecture closes the
DNS-resolver attestation blind spot that comparable build tools
leave open, and it forces a strict identity-asymmetry between
controller-held client identity and declared server-side trust
anchors.

The relevant supporting ADRs are
[ADR-005](ADR-005-per-step-security-profile.md) (hardening profile),
[ADR-007](ADR-007-asymmetric-identity.md) (identity asymmetry),
[ADR-013](ADR-013-dsse-envelope-and-rekor.md) (DSSE+Rekor),
[ADR-022](ADR-022-network-opt-in-as-peer-list.md) (peer list as
network-opt-in, whose Phase-2 promise this ADR fulfills),
[ADR-024](ADR-024-ssh-known-hosts.md) (SSH known_hosts pattern), and
[ADR-025](ADR-025-ssh-agent-proxy.md) (ssh-agent-proxy pattern).

## Ratified decisions

Decisions are tagged with a stable identifier. Once ratified, they
do not change without explicit operator confirmation; if a later
decision supersedes one, the superseded item is annotated, not
deleted.

### D-series (architecture and protocol)

- **D9 (paket-scope).** `internal/transport` is the dedicated
  package for peer-connect-and-trust handling, including TLS
  verification primitives, trust-anchor types, and the host-format
  constraint. Egress-mediation work depends on this package.
- **D10 (type residence).** Trust-anchor types and the typed `Host`
  constraint live in `internal/transport`, not in `internal/lane`.
  Directional dependency: `internal/lane` imports `internal/transport`.
- **D11 (system-CA mode).** `system_ca` as a trust mode remains
  deferred (per ADR-021); no implicit-system-trust path exists in
  any strike code.
- **D12 (TLS version).** TLS 1.3 minimum. All TLS connections (the
  transport primitive, the DoT resolver, the TLS mediator's
  container-side and upstream sides) require TLS 1.3. Superseded in
  part by ADR-032: external-peer hops now floor at TLS 1.2.
- **D13 (identity capture).** Every TLS connection captures peer
  identity (cert chain, fingerprint, TLS version, cipher suite)
  for attestation. The capture is part of the transport primitive's
  return contract, not optional.
- **D14 (resolver host semantics: deferred).** Today the lane's
  `resolver.host` field is an IP literal used both as connection
  endpoint and as the only identifier; TLS verification is via
  fingerprint pin or CA bundle without hostname check. Planned:
  declare both IP (connection endpoint) and hostname (TLS SAN/CN
  verification target plus DNS cross-check target), with strike
  verifying that the declared hostname resolves to the declared
  IP via the resolver itself. Documented in
  `docs/DNS-RESOLVER-CONFIGURATION.md` under "Future direction".
  Implementation deferred to a follow-up PR; basic Phase-2
  functionality does not require it.
- **D15 (port-853 default: deferred).** Today `resolver.host`
  requires an explicit port (`1.1.1.1:853`). Planned: omit the
  port and default to 853 per RFC 7858. Documented in
  `docs/DNS-RESOLVER-CONFIGURATION.md` under "Future direction".
  Implementation deferred; basic Phase-2 functionality does not
  require it.
- **D16 (resolver probe placement).** The DoT-resolver
  pre-flight probe (PR-17) runs at `strike run` time, after
  `lane.Parse` returns successfully, not inside `lane.Parse`.
  Rationale: `lane.Parse` is a pure offline syntactic and
  semantic check whose result is a property of the lane file
  alone. The probe outcome is a property of the environment
  at probe time (resolver reachability, cert validity at that
  moment). Folding the probe into Parse would make
  `strike validate` network-dependent, would silently
  invalidate today's validation result when tomorrow's
  resolver cert rotates, and would conflate input properties
  with environmental state. The "same input fails identically"
  principle from PR-15 (D-series predecessor formulation)
  governs input properties, not environment. Operator-facing
  reasoning is documented in
  `docs/DNS-RESOLVER-CONFIGURATION.md` ("Probe behavior").
- **D17 (ephemeral CA design).** The TLS mediator (PR-20)
  presents server certificates signed by an ephemeral
  Certificate Authority generated in the strike controller.
  The CA is per-lane-run (a fresh instance per `strike run`
  invocation), uses ECDSA P-256 for both CA and leaf certs,
  and has a 1h validity window starting at lane begin. The
  private key is held in process memory only and never
  written to disk; `EphemeralCA.Close` at lane end disposes
  the key material. Leaf certs inherit the CA's NotBefore
  and NotAfter, so all certs in a lane run expire together.
  Lanes running longer than 1h will see TLS validation
  failures mid-run; the TTL is hard-coded and not currently
  configurable, on the rationale that lanes are short by
  design and the in-memory-only key lifetime makes the
  validity window security-irrelevant. Implementation
  lives in `internal/transport/ca.go` (PR-18).
- **D18 (system CA bundle replacement).** Step containers
  in the strike architecture only legitimately reach
  strike-mediated peers. The system CA bundle pre-installed
  in a base image (`/etc/ssl/certs/ca-certificates.crt`,
  `/etc/pki/tls/certs/ca-bundle.crt`, and equivalents) has
  no value in this architecture: any TLS endpoint a step
  container talks to is mediated by strike's controller,
  verified against a lane-declared trust anchor, and
  re-presented to the container with a cert signed by the
  ephemeral CA. The system CA bundle therefore must be
  replaced by the ephemeral CA's public cert, not augmented
  with it. Augmenting would leave the system CAs in place,
  preserving a class of bypass if a netns-filter gap ever
  opened (a step reaches a non-mediated endpoint that
  happens to be signed by a system-bundle CA). PR-22 owns
  the mount mechanics: bind-mount the ephemeral CA cert
  over each known system-bundle path in the container's
  filesystem.
- **D19 (per-step resolver instance).** Each lane step gets
  its own `*resolver.Resolver` instance, bound at
  construction to that step's name and allowlist. There is
  no lane-wide resolver with active-step demultiplexing.
  Rationale: per-step instances bind step identity at
  construction (no source-IP-spoofing surface), contain
  failure blast radius to one step (a panic in one
  resolver does not take out parallel steps), and match the
  existing Step = Container = netns = Peer-Set containment
  boundary. PR-20 (TLS mediator) and PR-21 (egress filter)
  follow the same per-step-instance pattern; PR-22
  aggregates the three into a "network capsule" type whose
  lifecycle equals the step's. Implementation in
  `internal/resolver/` (PR-19); per-step lifecycle wiring
  in PR-22.
- **D20 (synthesizing resolver).** The allowlist resolver
  constructs DNS responses from the `[]netip.Addr` returned
  by its upstream-lookup function, not by relaying upstream
  wire-format responses. Rationale: bounds the wire-format-
  construction code to a fixed set of record types (A, AAAA),
  reducing the surface exposed to potentially-compromised
  step containers; aligns the captured QueryRecord with the
  decision a verifier later attests over (resolved IPs are
  what the TLS mediator dials).
- **D21 (per-step mediator instance).** Each lane step gets
  its own `*mediator.Mediator` instance, bound at
  construction to that step's peer-trust map and its
  ephemeral CA. There is no shared lane-wide mediator with
  active-step demultiplexing. Rationale parallels D19
  (per-step resolver): permissions baked in at construction
  (no per-connection step lookup), attestation correctness
  (step identity is the instance's identity, no source-IP
  indirection), failure isolation (a handshake-handler
  panic does not affect parallel steps), and capsule
  alignment (PR-22 aggregates per-step resolver + mediator
  + filter). Implementation in `internal/mediator/`
  (PR-20).
- **D22 (SNI-preserving split TLS).** The mediator
  decrypts container-side TLS using ephemeral-CA-signed
  leaves and re-encrypts upstream-side TLS against the
  lane-declared trust anchor; the SNI from the container's
  ClientHello drives both the leaf-cert issuance and the
  upstream handshake's `ServerName`. Pass-through TCP
  proxying is architecturally impossible because the
  container's trust store contains only the ephemeral CA;
  a direct container-to-upstream handshake would fail
  cert verification. Split TLS also enables per-peer
  attestation (capturing the upstream's verified identity
  requires that the mediator perform the upstream
  handshake) at the cost of plaintext flowing through the
  controller, which is consistent with strike's existing
  trust posture (the controller already holds signing
  keys, secrets, and runtime attestations in memory).
- **D23 (rootless backend: pasta; Podman >= 5.0).** Strike
  uses pasta (from the passt project) as its rootless
  network backend, configured per step via
  `--network=pasta:<options>` in the Podman REST API.
  Minimum Podman version is 5.0; older versions are not
  supported. Rationale documented in
  [SPIKE-rootless-netns-backend.md](SPIKE-rootless-netns-backend.md).
  Implementation in `internal/egress/` (PR-21); version
  gate at runtime in PR-22.
- **D24 (egress filter mechanism: splice-only + selective
  port forwarding).** The per-step egress filter is
  implemented by launching pasta with `--splice-only` (no
  tap interface in the container's namespace; only
  loopback) and two `-T <addr>/<port>` forwards: one for
  the step's resolver, one for the step's mediator. With
  no tap device, the container's namespace has no route
  to any non-loopback address; the only paths out of the
  namespace are the two splice forwards. This produces
  the operationally-desired property (container egress
  restricted to resolver and mediator) without any
  explicit deny-list: there is nothing to deny because
  there is nothing to permit. Implementation in
  `internal/egress/` (PR-21). IPv6 egress is out of scope
  for the initial implementation; the builder function
  panics on IPv6 inputs as a programming-error contract.
  Superseded in part by ADR-033: the two fixed `-T` forwards are now a
  variable set (resolver, mediator, plus one per SSH peer), and per-step
  distinctness lives in the host port, not a per-step address.
- **D25 (NetworkCapsule aggregate).** PR-22 introduces
  `internal/capsule/NetworkCapsule`, a per-step aggregate
  bundling the allowlist DNS resolver (PR-19), the TLS mediator
  (PR-20), and the pasta egress filter args (PR-21) into a
  single lifecycle. Constructed per mediated step (see D26);
  shares the lane-wide ephemeral CA (PR-18, D17) by pointer.
  The capsule owns the resolver/mediator listener lifecycle,
  the errgroup running their serve goroutines, and the records
  aggregation; it does not own the container lifecycle. Per-step
  loopback addresses are pre-computed by the pure function
  `capsule.AllocateAddresses`, in lane-file order, so the same
  lane yields the same step-to-IP mapping every run (no
  stateful allocator, no mutex; the determinism rests on
  Instruction 36's deterministic DAG plus pure pre-allocation).
  Rationale: the Phase-2 components have orthogonal
  responsibilities but a shared per-step lifecycle, and
  centralising it into one tested unit beats inlining ~30 lines
  of listener-binding and errgroup coordination per step,
  especially under parallel execution.
- **D26 (HTTPS-only mediation dispatch).** A step in PR-22 uses
  pasta-mediation iff it has at least one HTTPS peer AND no SSH
  peers. Pasta `--splice-only` removes the tap interface,
  leaving only loopback and declared splice forwards: HTTPS
  flows through the mediator's loopback splice (works), OCI is
  controller-side (no container network needed), but SSH needs
  outbound TCP/22 to the peer host (incompatible with
  splice-only without extra forwards). PR-22 takes the
  conservative scope: HTTPS-without-SSH steps get mediation;
  any-SSH steps keep existing bridge-network behaviour (ADR-024
  known_hosts, ADR-025 agent proxy); OCI-only or no-peer steps
  keep `--network=none`. Lane authors mixing HTTPS and SSH in
  one step can split into two steps to mediate the HTTPS half.
  PR-23 extends dispatch to mixed HTTPS+SSH steps via
  per-SSH-peer splice forwards (resolved IP plus port 22).
  Superseded by ADR-033 D28: the HTTPS-without-SSH restriction is
  removed. Every step container runs under a capsule; SSH peers are
  mediated by per-peer raw-TCP forwards (D27), and peer-less steps get
  an empty-allowlist capsule in place of `--network=none`.
- **D27 (SSH peer egress port-mux).** Each SSH peer of a step gets a
  strike-assigned container-side loopback port (`SSHContainerPortBase +
  k`, never 22) and a host-side raw-TCP forward through the capsule.
  strike resolves the upstream via the DoT resolver, dials it, and
  splices bytes; it does not terminate or inspect SSH. The per-peer
  port mapping is injected as an `ssh_config` referenced via `-F`. Port
  22 is unforwarded so a config-ignoring connection fails closed. See
  ADR-033.
- **D28 (universal capsule; no network-mode switch).** `--network=none`
  and `--network=bridge` are removed. Every step container runs under a
  per-step capsule with pasta `--splice-only`; peer-less steps get an
  empty allowlist (resolver NXDOMAIN-all, mediator deny-all). Applies to
  all four container paths (run, state-capture, Kubernetes deploy,
  custom deploy). See ADR-033.

### SD-series (schema topology)

- **SD-1 (transport package name).** `internal/transport` (matches D9
  / D10).
- **SD-2 (resolver schema placement).** Lane has a top-level
  `resolver:` field. Not a `#Peer` discriminator variant. Not under
  `#LaneDefaults`. The resolver is mandatory; a lane without one is
  invalid.
- **SD-3 (type generalization).**
  - `#HTTPSTrust` is renamed to `#TLSTrust`. The trust-anchor
    discriminated union (`#FingerprintTrust | #CABundleTrust`) is
    protocol-agnostic; the rename enables reuse by future TLS-trusted
    peer kinds (NTS-KE for trusted NTP, secured logging endpoints,
    etc.) without further schema migration.
  - A new typed `#Host` constraint is introduced (analog to `#AbsPath`,
    `#RelPath`). All existing `host: string & =~"..."` fields that
    use the standard host pattern are refactored to `host: #Host`.
    The OCI registry constraint (different format, includes path
    segments) is not touched.
  - `#TLSTrust` and `#Host` both live in `internal/transport`.

### Posture decisions (carried across PRs)

- **Pre-beta posture.** Breaking schema changes are acceptable
  without migration notices. No backward-compatibility-preservation
  language ("Phase 1 / Phase 2 / historical / earlier revision /
  migration") is introduced for non-existent prior states; it is
  acceptable for genuine present-state descriptions of partially
  implemented work and is removed in the same PR that completes the
  work.
- **No-MITM-position rebuttal.** ADR-028 contains the canonical
  argument for why TLS termination in the controller is structurally
  different from privacy-violating interception. Future PRs do not
  need to re-litigate this; reference the ADR.
- **No escape hatches.** ADR-028 commits to universal mediation. No
  per-peer opt-out, no compatibility mode, no raw-TCP allowlist, no
  plain-HTTP path. Adding support for a new protocol means adding
  controller-side mediator code, not a lane-configuration option.
- **In-memory CA preference.** Ephemeral CA private-key material
  never reaches disk. Generation, signing, and disposal happen in
  controller-process memory. The public CA certificate is
  materialised on disk only as a read-only mount source for step
  containers, for the lifetime of the lane run. This is the design
  default for PR-18 (ephemeral CA infrastructure).

## PR sequence

### Phase 1: Transport primitive

| PR | Title | Status | Depends on | Hash (after merge) |
|----|-------|--------|-----------|-------------------|
| PR-14 | Transport-package bootstrap (move/rename/generalize types) | Done | -- | -- |
| PR-15 | DNS-resolver declaration in lane schema | Done | PR-14 | -- |
| PR-16 | `internal/transport` TLS-primitive (`DialVerified`, `BuildTLSConfig`) | Done | PR-14 | -- |
| PR-17 | First production consumer (DoT resolver pre-flight) | Done | PR-16 | -- |

Phase 1 has independent value: PR-16 alone is consumed by
[ADR-014](ADR-014-audit-pipeline.md) hardening work and `strike
verify`, even before Phase 2 lands. PR-15's resolver surface has
two deferred enhancements (D14: combined IP + hostname; D15:
port-853 default) documented in
[DNS-RESOLVER-CONFIGURATION.md](DNS-RESOLVER-CONFIGURATION.md).

### Phase 2: Mediation subsystem

| PR | Title | Status | Depends on |
|----|-------|--------|-----------|
| PR-18 | Ephemeral per-lane-run CA (in-memory) | Done | PR-14 |
| PR-19 | Per-step DNS allowlist resolver | Done | PR-17 |
| PR-20 | Per-step TLS mediator | Done | PR-17, PR-18 |
| PR-21 | Per-step egress filter (pasta args) | Done | PR-19, PR-20 |
| PR-22 | Integration: NetworkCapsule, executor wiring, version gate | Done | PR-17 .. PR-21 |
| PR-23 | SSH-peer pasta integration (mixed HTTPS+SSH steps) | Done (subsumed by ADR-033) | PR-22 |
| PR-24 | SSH mediation under unified architectural roof | Done (subsumed by ADR-033) | PR-22 |

The Phase-2 work is complete.

### Phase 3: Cross-cutting and downstream

| Item | Title | Status |
|------|-------|--------|
| mTLS-ADR | Client-cert as typed Secret, mediator authenticates on behalf of step | Future |
| ADR-014 hardening | Audit-sink transport consumes PR-16 primitive | Separate track |
| `strike verify` | Consumes Phase-1 primitive plus PR-23 attestation schema | Separate track |
| Documentation | Cloudflare/Quad9/Google/IPFire resolver examples; D14/D15 deferred decisions | Done (PR-15) |
| ADR-022 update | Drop "Phase 1 is declaratory" once Phase 2 complete | Tracked with PR-22 |

## Conventions for instruction-writing

All conventions established in earlier PRs carry forward:

- **Numbered instruction files** in repo root, format
  `NN_TOPIC_NAME.md`, with `NN` matching the next free integer in
  the existing sequence.
- **Anti-initiative clause** in every instruction. The phrasing
  shifts per PR but always includes: do not write new ADRs, do not
  introduce em-dashes, do not touch files outside the named list,
  stop and ask if before-snippets do not match the working tree.
- **Confirmation gate** for schema-touching PRs. Operator confirms
  before instruction-writing if any schema decision is unsettled.
  For PR-14 specifically, SD-1/2/3 are ratified -- no further
  confirmation needed inside the PR.
- **Exact before/after snippets**, not templates. Claude Code
  handles deltas poorly; clean replace-this-with-that sequences
  are preferred.
- **Commit-message style.** Body describes what changed and why,
  no external review-document references, no "Resolves: ..." footer
  pointing to artifacts outside the codebase. Subject line in
  conventional-commit form (`feat:`, `refactor:`, `test:`, `docs:`,
  `fix:`).
- **Quality gates.** Standard five-gate sequence in every PR:
  golangci-lint, deadcode, go test -race, govulncheck, build.
- **Acceptance criteria with grep verification** where applicable.
  Each criterion either compiles to a `git diff --stat` check, a
  `grep -n` invariant, or a test that exists/passes.

## Cross-references

- Architectural: [ADR-028](ADR-028-step-container-egress-mediation.md)
  is the authoritative architecture document. This roadmap derives
  its decisions from there.
- Supporting ADRs: ADR-005, ADR-007, ADR-013, ADR-021, ADR-022,
  ADR-024, ADR-025 (see "Architectural target" above for the role
  of each).
- Earlier inconsistency-resolution work: complete; only Cluster-1
  (bootstrap chain) remains as a separate track per D7.

## Current status

**Phase 1: complete; Phase 2: integrated.** PR-14 through PR-17
landed Phase 1. PR-18 added the ephemeral per-lane-run CA. PR-19
added the per-step DNS allowlist resolver. PR-20 added the
per-step TLS mediator. PR-21 added the per-step egress filter.
PR-22 wires them together: a `NetworkCapsule` aggregate per
HTTPS-mediated step (D25), deterministic per-step loopback
addresses via `capsule.AllocateAddresses`, a lane-wide ephemeral
CA written to `/tmp/strike-lane-<id>-*/ca.pem` and bind-mounted
into each mediated container, a Podman 5.0+ version gate in
`initEngine`, and dispatch in `executeContainerStep` (D26:
HTTPS-without-SSH -> capsule; otherwise existing behaviour).
Next is PR-23 (SSH-peer pasta integration), extending dispatch
to mixed HTTPS+SSH steps. Subsequent decisions (mTLS schema
specifics, audit-sink transport hardening, Rekor via
DialVerified) remain on the Phase-3 track.

**Snapshot at roadmap creation**: `2b7b3f7c4b7313ae17a70e98b175f2e0706578e1`
(post-PR-13: peer-coverage gaps closed; inconsistency-review backlog
empty except Cluster-1 bootstrap track).

**Snapshot after PR-14**: `041ce4a31c9615f054c468ad2280282f8b10174b`
(post-PR-14: internal/transport package exists with TLSTrust/Host
types; trust-anchor types moved from lane to transport; HTTPSTrust
renamed to TLSTrust; #Host typed constraint introduced).

**Snapshot after PR-15**: `36c6881b0b290a69e6659b8811d33a04cb815809`
(post-PR-15): Every lane must now declare exactly one DNS resolver
under a new top-level `resolver:` field. validateResolver runs in
lane.Parse immediately after typed deserialisation, in the same
position as ValidatePaths.

**Snapshot after PR-16**: `5eac7e5a07031127742610fad6aacf02cdc18453`
(post-PR-16: transport TLS-primitive available; DialVerified,
BuildTLSConfig, VerifiedConn, ConnectionIdentity; TLS 1.3
minimum hard-coded; SNI derived from addr; integration test
behind build tag).

**Snapshot after PR-17**: `eaeb68ea6f9a0bcabcb223945cdc84027fd5fce9`
(post-PR-17: transport DoT client available; LookupHost and
ProbeResolver added; strike run performs pre-flight resolver
probe after lane.Parse; D16 records placement rationale).

**Snapshot after PR-18**: `e3aa2b60b95d402e7b721da4eb0b11a7cbba2999`
(post-PR-18: internal/transport/ca.go provides EphemeralCA
with New, GetCertificate, PublicCertPEM, Fingerprint, Close;
per-lane-run lifetime, ECDSA P-256, 1h validity, in-memory
keys; mount-agnostic surface defers materialisation to
PR-22; D17 and D18 ratified).

**Snapshot after PR-19**: `f90c286b0042001a6d7c7b8d7225982ce2bc9c7b`
(post-PR-19: internal/resolver/ provides per-step Resolver
with New, Serve, Records, Close; synthesizing server,
stdlib-only wire format; D19 and D20 ratified).

**Snapshot after PR-20**: `c7cc86fcce667df3cc1739453735885953feb9ca`
(post-PR-20: internal/mediator/ provides per-step Mediator
with New, Serve, Records, Close; split-TLS proxy with
SNI-allowlist gate, ephemeral-CA-signed container-side
leaves, lane-trust-anchor-verified upstream side, identity
capture per connection; D21 and D22 ratified).

**Snapshot after PR-21**: `344d92de1de20fd69370e1290bb739af58e07903`
(post-PR-21: internal/egress/ provides BuildPastaArgs as a
pure function from (resolverAddr, mediatorAddr) to pasta
argument list; D24 ratified; Phase 2 library shelf
complete; PR-22 is the integration PR).

**Snapshot after PR-22**: `a0e63ddf1947513481e744ec52bfe97302d9bdc3`
(post-PR-22: internal/capsule/ provides NetworkCapsule plus the
pure AllocateAddresses; container.RunOpts gains PastaArgs and
DNSServers; container.RequireVersion fail-fasts on Podman < 5.0;
executor.Run integrates Capsule + CABundlePath; cmdRun builds
the lane-wide CA and pre-allocates mediated-step addresses; D25
and D26 ratified).

The DoT resolver's observed identity is now recorded in the deploy
attestation as `resolver` (`#ResolverRecord`), captured once per
lane run at the pre-flight probe handshake (ADR-030). This is the
one controller-side connection record beyond the engine record;
OCI registries are not recorded (content trust via digest pin).
The per-peer container `connections` surface remains future work.

The per-step resolver synthesizes the loopback address 127.0.0.1
for allowed names rather than returning the real upstream IP:
under pasta `--splice-only` the container can reach only that
loopback address, where the step's mediator listens, and the
mediator performs the real upstream resolution. The container
always sees the resolver at 127.0.0.1:53 and the mediator at
127.0.0.1:443; pasta `-T`/`-U` forward those to the step's distinct
unprivileged host ports. Per-step distinctness lives in the host
port, not the address, because pasta `-T`/`-U` accept no listening
address (only `-t`/`-u` do); host ports are allocated
deterministically in lane-file order, which keeps them collision-
free under step parallelism and byte-stable per lane. Each step
has its own netns, so the shared loopback never collides.
SSH peer egress is now mediated by per-peer raw-TCP forwards through
the capsule (ADR-033 D27), and the `--network=none`/`--network=bridge`
fallbacks are removed: every step container runs under a capsule, with
an empty allowlist for peer-less steps (D28). This holds across all
four container paths. Phase 2 is complete. Phase 3 (mTLS via
controller-held client cert, audit-sink transport hardening, Rekor via
DialVerified) is a closing/documentation track: no further egress
mediation is built.

