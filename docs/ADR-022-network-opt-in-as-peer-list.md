# ADR-022: Network Opt-in as a Typed Peer List

## Status

Accepted. Updates the network-opt-in surface described in ADR-005;
realises the "Peers are declared" principle from ADR-007.

## Context

ADR-005 set the per-step security profile and described the network
opt-in as a single bit (`network: true` on the step). ADR-007
established that network interaction is a typed trust contract: any
step that uses the network must enumerate its peers with the
appropriate trust anchor for each peer type. A bool field cannot
carry that contract, and the consuming code paths in deploy had no
peer information available -- so they defaulted to `--network=host`,
which strips the netns isolation that ADR-005 was supposed to
guarantee. The bool form was therefore not just incomplete but
actively undermined the ADR-005 hardening profile for deploy steps
and state captures.

The schema also permitted lane authors to opt into network access
without any indication of where that access would terminate. A
reviewer reading a lane file with `network: true` had no way to
distinguish "fetches from a known package mirror" from "fetches
from arbitrary hosts on the open internet". The attestation
likewise could not record what trust the step actually exercised.

## Decision

The lane schema uses a typed peer list, not a bool:

- `Step.peers: [...#Peer]` replaces the previous `Step.network: bool`.
- `StateCapture.peers: [...#Peer]` replaces `StateCapture.network: bool`.
- `LaneDefaults.network` is removed.

`#Peer` is a discriminated union over `#HTTPSPeer`, `#SSHPeer`, and
`#OCIPeer`. Each peer type carries the trust anchor appropriate to
its protocol: certificate fingerprint or CA bundle path for HTTPS
(and as an optional refinement for OCI registry connections),
known_hosts entries for SSH, image digests for OCI (covered by
`#ImageRef`).

Empty or absent peer list means the step runs with `--network=none`.
A non-empty peer list means `--network=bridge`. The list itself is
recorded in the deploy attestation (`Attestation.peers`, keyed by
step name) and signed under the DSSE envelope. State-capture peers
are recorded on the corresponding `StateSnap`.

This is Phase 1: declaratory. The peer list is the signed-attestation
record of what trust the step was supposed to exercise; the kernel
sees only the bridge/none switch. Per-peer enforcement
(`extra_hosts` injection, CA-bundle bind mounts, ssh-agent socket
forwarding, egress filtering) is Phase 2 and gets its own ADR when a
concrete enforcement story is needed.

The deploy paths (Kubernetes, custom) use the same peer-driven
mechanism as run steps. The `--network=host` setting is removed
from all controller code paths. A Kubernetes deploy that needs to
reach an API server must declare it as an HTTPS peer with the
appropriate trust anchor.

## Consequences

- ADR-005's "the opt-in surface is one bit" sentence is now
  historical; the surface is a typed list. The hardening posture is
  unchanged; the opt-in is wider in expressiveness but narrower in
  what each declaration permits.
- Deploy attestations gain a `peers: {step_name: [...#Peer]}` field
  that records the network exposure of the deploy step and its
  transitive predecessors. Verifiers can now answer "which peers
  did this build chain contact" from the signed attestation alone.
- Lane authors who previously wrote `network: true` write a peer
  list. A bool was a one-keystroke decision; a peer list is several
  lines, deliberately. The peer list is the record of a security
  decision; making it visible in the lane source is the point.
- The `--network=host` regression in deploy is closed. Deploy
  containers receive the same network-hardening treatment as run
  containers.
- The system-CA-only HTTPS peer remains a deferred extension
  (ADR-021). When a concrete production case appears, a new peer
  variant or a new trust mode is added.
- The git-protocol (`git://`) workflow described in earlier
  versions of `docs/local-development.md` Option A is not
  expressible in the typed peer schema (the protocol has no trust
  anchor); the recommended local-iteration path is the HTTPS
  variant (Option B).

## Principles

- Peers are declared
- Identity is asymmetric
- CUE first
- No root (the network opt-in cannot weaken the hardening profile)
