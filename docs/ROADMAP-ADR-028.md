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
  container-side and upstream sides) require TLS 1.3.
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
| PR-16 | `internal/transport` TLS-primitive (`DialVerified`, `BuildTLSConfig`) | Planned | PR-14 | -- |
| PR-17 | First production consumer (Rekor, container-engine TLS) | Planned | PR-16 | -- |

Phase 1 has independent value: PR-16 alone is consumed by
[ADR-014](ADR-014-audit-pipeline.md) hardening work and `strike
verify`, even before Phase 2 lands. PR-15's resolver surface has
two deferred enhancements (D14: combined IP + hostname; D15:
port-853 default) documented in
[DNS-RESOLVER-CONFIGURATION.md](DNS-RESOLVER-CONFIGURATION.md).

### Phase 2: Mediation subsystem

| PR | Title | Status | Depends on |
|----|-------|--------|-----------|
| PR-18 | Ephemeral per-lane-run CA (in-memory) | Planned | PR-14 |
| PR-19 | DNS allowlist resolver (DoT via transport) | Planned | PR-15, PR-16 |
| PR-20 | TLS mediator (terminate, verify upstream, re-establish) | Planned | PR-16, PR-18 |
| PR-21 | Netns egress filter (after backend spike) | Planned | engineering spike first |
| PR-22 | Integration: CA mount, filter setup, mediator wiring | Planned | PR-18..PR-21 |
| PR-23 | Attestation surface extension | Planned | PR-22 |
| PR-24 | SSH mediation under unified architectural roof | Planned | PR-21 |

Phase 2 requires an engineering spike before PR-21: netavark vs.
custom CNI plugin vs. pasta evaluation, with criteria (rootless
maturity, test coverage, host-OS compatibility). The spike is not
a code PR; it produces a short evaluation document (`docs/SPIKE-rootless-netns-backend.md`
or similar) that grounds the PR-21 implementation choice.

### Phase 3: Cross-cutting and downstream

| Item | Title | Status |
|------|-------|--------|
| mTLS-ADR | Client-cert as typed Secret, mediator authenticates on behalf of step | Future |
| ADR-014 hardening | Audit-sink transport consumes PR-16 primitive | Separate track |
| `strike verify` | Consumes Phase-1 primitive plus PR-23 attestation schema | Separate track |
| Documentation | Cloudflare/Quad9/Google/IPFire resolver examples; D14/D15 deferred decisions | Done (PR-16) |
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

**Phase 1: in progress.** PR-14 and PR-15 landed (transport-package
bootstrap, DNS-resolver declaration). Next PR is PR-16
(`DialVerified`, `BuildTLSConfig`). Subsequent decisions (rootless
backend spike, mTLS schema specifics, etc.) will be documented here
as they're made.

**Snapshot at roadmap creation**: `d17226dcd485ca61eacce8f46b11fc5c42cc0d4552b529dd0ea12ca235276992`
(post-PR-13: peer-coverage gaps closed; inconsistency-review backlog
empty except Cluster-1 bootstrap track).

**Snapshot after PR-14**: `a35971bdb32544d2a927164e4f80618eeb7396d153f2b1311efd929764bc8630`
(post-PR-14: internal/transport package exists with TLSTrust/Host
types; trust-anchor types moved from lane to transport; HTTPSTrust
renamed to TLSTrust; #Host typed constraint introduced).
