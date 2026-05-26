# Architecture Decision Records

This index lists strike's architectural decision records (ADRs) in
historical-logical order. Numbering is permanent: an ADR is never
renumbered. When a decision is revised, a new ADR is created with a
`Supersedes:` reference; the older ADR's status changes to
`Superseded by ADR-NNN`.

The numbering is also a reading order. ADR-001 is the foundational
decision; later ADRs assume the earlier ones. Reading top-to-bottom
shows how the architecture was built up.

An ADR is content-stable: it is revised only by a later ADR that
sharpens or supersedes it, never by editing the original decision. Each
accepted ADR drives the next implementation phase, either as a single
instruction or as its own roadmap.

The mapping from an ADR to the design principles it concretizes lives in
that ADR's `## Principles` section, and only there. That section is the
single authoritative source for the mapping; it is unidirectional
(`DESIGN-PRINCIPLES.md` does not list ADRs back). When a new principle is
discovered, the existing ADRs are examined for it and mapped by *adding*
the assignment to their `## Principles` section -- nothing else in a
settled ADR changes.

The "By principle" view below is a collected aggregation of those
self-tags, not an independent record. It can be regenerated mechanically;
at minimum, every instruction that completes an ADR verifies, in its
acceptance criteria, that this index reflects that ADR's `## Principles`
section. A CI guard (`make lint-adr-index`) fails when an ADR file is not
referenced here at all.

## By number

| #   | Title                                                              | Status   | Principles                                       |
|-----|--------------------------------------------------------------------|----------|--------------------------------------------------|
| 001 | [Container engine via REST API, not subprocess execution](ADR-001-engine-via-api-not-exec.md) | Accepted | No exec; No shell; Code is liability             |
| 002 | [No shell in the execution path](ADR-002-no-shell-in-execution-path.md)                       | Accepted | No shell; Code is liability                      |
| 003 | [Rootless end-to-end execution](ADR-003-rootless-end-to-end.md)                               | Accepted | No root; No exec                                 |
| 004 | [CUE schemas as the single source of truth](ADR-004-cue-as-single-source-of-truth.md)         | Accepted | CUE first; Code is liability                     |
| 005 | [Hardened container profile, not lane-configurable](ADR-005-hardened-container-profile-non-configurable.md) | Accepted | No root; Code is liability; Peers are declared; Enforcement is structural |
| 006 | [Secrets are a typed primitive, not a string](ADR-006-secrets-as-typed-primitive.md)          | Accepted | Secrets are typed; Code is liability; Enforcement is structural |
| 007 | [Asymmetric identity for client auth and server trust](ADR-007-asymmetric-identity.md)        | Accepted | Identity is asymmetric; Peers are declared       |
| 008 | [Cryptographic primitives -- ECDSA P-256, scrypt + secretbox, crypto/rand](ADR-008-cryptographic-primitives.md) | Accepted | Digest-pinned references; Code is liability; Identity is asymmetric |
| 009 | [Bootstrap reproducibility proof via stage 2 / stage 3 binary equality](ADR-009-bootstrap-reproducibility-proof.md) | Accepted | Reproducibility is enforced; Digest-pinned references; No shell |
| 010 | [Typed DAG edges carry resolved references](ADR-010-typed-dag-edges.md)                       | Accepted | Code is liability; CUE first; Reproducibility    |
| 011 | [Host filesystem cannot enter the DAG](ADR-011-sources-elimination.md)                        | Accepted | Digest-pinned references; Code is liability; Reproducibility |
| 012 | [Engine identity captured in every attestation](ADR-012-engine-identity-capture.md)           | Accepted | Runtime is attested; Identity is asymmetric; Digest-pinned references |
| 013 | [DSSE envelope shape and Rekor submission](ADR-013-dsse-envelope-and-rekor.md)                | Accepted | Runtime is attested; Code is liability; Digest-pinned references; Identity is asymmetric |
| 014 | [Audit transport for forensic accountability](ADR-014-audit-transport.md)                     | Accepted | Runtime is attested; Secrets are typed; Code is liability |
| 015 | [All time access dispatched through internal/clock](ADR-015-internal-clock-dispatch.md)       | Accepted | Reproducibility is enforced; Code is liability; CUE first |
| 016 | [State-drift recording, not detection or action](ADR-016-drift-recording-posture.md)          | Accepted | Code is liability; Runtime is attested; Reproducibility; Digest-pinned references; Secrets are typed |
| 017 | [Cross-validation through golden vectors and JSON Schema export](ADR-017-cross-validation-vectors.md) | Accepted | CUE first; Reproducibility; Code is liability; Digest-pinned references |
| 018 | [Cryptographic test material is ephemeral](ADR-018-ephemeral-test-material.md)                | Accepted | Secrets are typed; Code is liability; Digest-pinned references |
| 019 | [SBOMs as OCI 1.1 referrer artifacts](ADR-019-sbom-as-oci-referrer.md)                        | Accepted | Runtime is attested; Digest-pinned references; Identity is asymmetric; Code is liability |
| 020 | [Storage driver selection and host environment plumbing](ADR-020-storage-driver-and-host-plumbing.md) | Accepted | No root; Code is liability; Digest-pinned references |
| 021 | [Deferred extensions](ADR-021-deferred-extensions.md)                                         | Accepted | Code is liability; Digest-pinned references      |
| 022 | [Network opt-in as a typed peer list](ADR-022-network-opt-in-as-peer-list.md)                 | Accepted | Peers are declared; Identity is asymmetric; CUE first; No root; Enforcement is structural |
| 023 | [Pointer arguments require justification](ADR-023-pointer-arguments-require-justification.md)  | Accepted | Code is liability                                |
| 024 | [SSH peer server-trust enforcement](ADR-024-ssh-peer-server-trust-enforcement.md)              | Accepted | Peers are declared; Identity is asymmetric; No root; Code is liability; Enforcement is structural |
| 025 | [SSH peer client-identity enforcement](ADR-025-ssh-peer-client-identity-enforcement.md)        | Accepted | Identity is asymmetric; No root; Code is liability; Peers are declared; Enforcement is structural |
| 026 | [Containers as sole inter-step storage object](ADR-026-containers-as-sole-inter-step-storage.md) | Accepted | Containers are the only storage; Code is liability; Digest-pinned references; Reproducibility |
| 027 | [Subpath selection on inputs](ADR-027-input-subpath-selection.md) | Accepted | Code is liability; CUE first; Digest-pinned references; Reproducibility |
| 028 | [Step-Container Egress Mediation](ADR-028-step-container-egress-mediation.md) | Accepted | No root; Peers are declared; Identity is asymmetric; Enforcement is structural; Runtime is attested; Code is liability |
| 029 | [Peers are container-egress contracts; the OCI peer type is removed](ADR-029-peers-are-container-egress.md) | Accepted | Peers are declared; Identity is asymmetric; Digest-pinned references; Enforcement is structural; Code is liability |
| 030 | [Controller-side connection recording follows the trust chain, not the connection count](ADR-030-controller-side-connection-recording.md) | Accepted | Runtime is attested; Identity is asymmetric; Digest-pinned references; Code is liability |
| 031 | [pasta --splice-only Toolchain Dependency and Platform Support](ADR-031-pasta-splice-only-dependency.md) | Accepted | No root; Peers are declared; Digest-pinned references; Reproducibility; Code is liability; Enforcement is structural |
| 032 | [Peer TLS version floor](ADR-032-peer-tls-version-floor.md) | Accepted | Restricted by default; Peers are declared; Code is liability |
| 033 | [SSH Peer Egress and Unified Capsule Mediation](ADR-033-ssh-peer-egress-and-unified-mediation.md) | Accepted | Peers are declared; Identity is asymmetric; No root; Runtime is attested; Code is liability; Enforcement is structural |
| 034 | [Symlink Containment at Wrap and Mount](ADR-034-symlink-containment.md) | Accepted | Restricted by default; Reproducibility; Digest-pinned references; Code is liability; Enforcement is structural |
| 035 | [Build payload stays in the engine; outputs are workdir-volume projections](ADR-035-build-payload-in-engine.md) | Accepted | Containers are the only storage; Enforcement is structural; Reproducibility; Digest-pinned references; CUE first; Code is liability |
| 036 | [Engine-native step input delivery](ADR-036-engine-native-input-delivery.md) | Accepted | Containers are the only storage; Digest-pinned references; Reproducibility; Code is liability; Enforcement is structural |
| 037 | [Two trust layers toward the engine](ADR-037-two-engine-trust-layers.md) | Accepted | Runtime is attested; Identity is asymmetric; Code is liability; Reproducibility; Enforcement is structural |
| 038 | [Protocol-mediated SSH via a control-plane front](ADR-038-protocol-mediated-ssh.md) | Proposed | No shell; Peers are declared; Identity is asymmetric; Runtime is attested; Digest-pinned references; Code is liability; Enforcement is structural |

## By principle

This view shows which ADRs concretize each design principle. Most
ADRs touch more than one principle, so entries appear under multiple
headings.

### Code is liability

ADR-001, ADR-002, ADR-004, ADR-005, ADR-006, ADR-008, ADR-010,
ADR-011, ADR-013, ADR-014, ADR-015, ADR-016, ADR-017, ADR-018,
ADR-019, ADR-020, ADR-021, ADR-023, ADR-024, ADR-025, ADR-026, ADR-027,
ADR-028, ADR-029, ADR-030, ADR-031, ADR-032, ADR-033, ADR-034, ADR-035,
ADR-036, ADR-037, ADR-038.

### No shell

ADR-001, ADR-002, ADR-009, ADR-038.

### No exec

ADR-001, ADR-003.

### No root

ADR-003, ADR-005, ADR-020, ADR-022, ADR-024, ADR-025, ADR-028,
ADR-031, ADR-033.

### CUE first

ADR-004, ADR-010, ADR-015, ADR-017, ADR-022, ADR-027, ADR-035.

### Secrets are typed

ADR-006, ADR-014, ADR-016, ADR-018.

### Runtime is attested

ADR-012, ADR-013, ADR-014, ADR-016, ADR-019, ADR-028, ADR-030,
ADR-033, ADR-037, ADR-038.

### Peers are declared

ADR-005, ADR-007, ADR-022, ADR-024, ADR-025, ADR-028, ADR-029,
ADR-031, ADR-032, ADR-033, ADR-038.

### Identity is asymmetric

ADR-007, ADR-008, ADR-012, ADR-013, ADR-019, ADR-022, ADR-024,
ADR-025, ADR-028, ADR-029, ADR-030, ADR-033, ADR-037, ADR-038.

### External references are digest-pinned

ADR-008, ADR-009, ADR-011, ADR-012, ADR-013, ADR-016, ADR-017,
ADR-018, ADR-019, ADR-020, ADR-021, ADR-026, ADR-027, ADR-029,
ADR-030, ADR-031, ADR-034, ADR-035, ADR-036, ADR-038.

### Reproducibility is enforced, not hoped for

ADR-009, ADR-010, ADR-011, ADR-015, ADR-016, ADR-017, ADR-026, ADR-027,
ADR-031, ADR-034, ADR-035, ADR-036, ADR-037.

### Containers are the only storage

ADR-026, ADR-035, ADR-036.

### Restricted by default, relaxed only with reason

ADR-032, ADR-034.

### Enforcement is structural, not discretionary

ADR-005, ADR-006, ADR-022, ADR-024, ADR-025, ADR-028, ADR-029,
ADR-031, ADR-033, ADR-034, ADR-035, ADR-036, ADR-037, ADR-038.

## Format

Each ADR has these sections:

- **Status**: Proposed, Accepted, Deprecated, or Superseded by ADR-NNN.
- **Context**: the situation and forces that prompted the decision.
- **Decision**: what was chosen, stated as commitments rather than
  options.
- **Consequences**: what the decision implies for code, schema,
  workflow, and future change.
- **Principles**: cross-reference to design principles in
  `DESIGN-PRINCIPLES.md`.

ADRs are kept short by default. An ADR runs longer when the decision
required substantial alternative analysis or when the consequences
section needs a worked example.
