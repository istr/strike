# Architecture Decision Records

This index lists strike's architectural decision records (ADRs) in
historical-logical order. Numbering is permanent: an ADR is never
renumbered. When a decision is revised, a new ADR is created with a
`Supersedes:` reference; the older ADR's status changes to
`Superseded by ADR-NNN`.

The numbering is also a reading order. ADR-001 is the foundational
decision; later ADRs assume the earlier ones. Reading top-to-bottom
shows how the architecture was built up.

## By number

| #   | Title                                                              | Status   | Principles                                       |
|-----|--------------------------------------------------------------------|----------|--------------------------------------------------|
| 001 | [Container engine via REST API, not subprocess execution](ADR-001-engine-via-api-not-exec.md) | Accepted | No exec; No shell; Code is liability             |
| 002 | [No shell in the execution path](ADR-002-no-shell-in-execution-path.md)                       | Accepted | No shell; Code is liability                      |
| 003 | [Rootless end-to-end execution](ADR-003-rootless-end-to-end.md)                               | Accepted | No root; No exec                                 |
| 004 | [CUE schemas as the single source of truth](ADR-004-cue-as-single-source-of-truth.md)         | Accepted | CUE first; Code is liability                     |
| 005 | [Hardened container profile, not lane-configurable](ADR-005-hardened-container-profile-non-configurable.md) | Accepted | No root; Code is liability; Peers are declared   |
| 006 | [Secrets are a typed primitive, not a string](ADR-006-secrets-as-typed-primitive.md)          | Accepted | Secrets are typed; Code is liability             |
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

## By principle

This view shows which ADRs concretize each design principle. Most
ADRs touch more than one principle, so entries appear under multiple
headings.

### Code is liability

ADR-001, ADR-002, ADR-004, ADR-005, ADR-006, ADR-008, ADR-010,
ADR-011, ADR-013, ADR-014, ADR-015, ADR-016, ADR-017, ADR-018,
ADR-019, ADR-020, ADR-021.

### No shell

ADR-001, ADR-002, ADR-009.

### No exec

ADR-001, ADR-003.

### No root

ADR-003, ADR-005, ADR-020.

### CUE first

ADR-004, ADR-010, ADR-015, ADR-017.

### Secrets are typed

ADR-006, ADR-014, ADR-016, ADR-018.

### Runtime is attested

ADR-012, ADR-013, ADR-014, ADR-016, ADR-019.

### Peers are declared

ADR-005, ADR-007.

### Identity is asymmetric

ADR-007, ADR-008, ADR-012, ADR-013, ADR-019.

### External references are digest-pinned

ADR-008, ADR-009, ADR-011, ADR-012, ADR-013, ADR-016, ADR-017,
ADR-018, ADR-019, ADR-020, ADR-021.

### Reproducibility is enforced, not hoped for

ADR-009, ADR-010, ADR-011, ADR-015, ADR-016, ADR-017.

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
