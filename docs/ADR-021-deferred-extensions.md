# ADR-021: Deferred Extensions

## Status

Accepted (as a tracking record).

## Context

Several capabilities have been considered during strike's design,
deemed legitimate, and deliberately not implemented. They are
deferred for one of three reasons:

- *No production demand yet*. The capability would be correct to
  add, but no operator has requested it, and adding it
  speculatively violates "Code is liability".
- *Architecturally clear, but blocked on prerequisite work*. The
  shape is decided; the implementation depends on something else
  that has not been built.
- *Unresolved design tension*. The capability is wanted, but the
  design has tradeoffs that have not been worked through.

Without a record, deferred items either get re-debated each time
they come up, or get implemented during a related refactor without
the benefit of dedicated review. This ADR is the record. Each item
below has a brief context, the deferral reason, and the conditions
under which it would be revisited.

## Deferred items

### System CA opt-in for HTTPS peers

**What.** A lane field that opts into using the host's system
trust store for an HTTPS peer, instead of requiring an explicit
CA bundle or cert fingerprint per ADR-007.

**Why deferred.** The asymmetric-identity principle requires that
server identity be declared per peer. Allowing "use the system
store" is a legitimate shorthand for cases where the peer is a
public service whose CA chains to a root the OS already trusts
(e.g. fetching a vendor's package index). The risk is that
operators reach for it when they should be pinning, weakening the
overall trust posture.

**Revisit when.** A concrete production case appears where
explicit pinning is impractical (e.g. a vendor whose certificate
rotates faster than the lane definition can be updated). Until
then, operators pin explicitly or run the fetch through a step
that brings the trust anchor with it.

### Additional container engines (Docker, containerd, CRI-O)

**What.** Engine-API support for non-podman container engines.

**Why deferred.** Strike's controller talks to a single engine
through a single interface (`container.Engine` in
`internal/container`). Adding a second engine implementation is
mechanical -- a new package implementing the same interface --
but requires a real reason: a deployment environment where podman
is not viable, or a specific feature only a different engine
provides. So far, neither has materialized.

**Revisit when.** A consumer needs strike on a host where podman
is not available (e.g. a Kubernetes-native runtime where
containerd is the only option). At that point the right shape is
likely a `container.Engine` implementation backed by the CRI
client, with strike's existing rootless-and-hardening posture
preserved.

### Unikraft / Firecracker / VM-isolated steps

**What.** A lane step variant that runs the workload in a
microVM rather than a container, for stronger isolation between
mutually distrusting steps.

**Why deferred.** This is a separate isolation tier with a
different threat model. Strike's current design assumes that step
containers may be malicious but cannot escape the rootless
boundary; for use cases where that assumption is too weak (running
arbitrary user-uploaded code, multi-tenant CI with hostile peers),
microVM isolation is correct.

**Revisit when.** A specific multi-tenant or hostile-peer scenario
appears. The integration shape is plausible (Firecracker exposes
a similar API to a container engine), but the specific isolation
guarantees and trust contracts are different enough that they
deserve their own ADR rather than being shoehorned into the
existing engine interface.

### Step output verification beyond magic bytes and size

**What.** Stronger validation of step outputs: format-level
parsing (is this a well-formed PE binary? a valid wheel? a
syntactically correct JSON schema?), content scanning (does the
output contain known-bad patterns?), or cryptographic checks
(does the binary's embedded signature verify?).

**Why deferred.** Magic-byte and size validation catches the
class of "completely wrong output" errors at low cost. Format-
level validation is per-format and does not generalize; content
scanning is the domain of dedicated tools; cryptographic checks
are the domain of the consumer who knows what trust anchor to
apply. None of them has a one-size-fits-all answer that strike
should embed.

**Revisit when.** A specific deployment domain (e.g. signed
package distribution) needs a per-format check that is small,
universal within that domain, and fails closed. At that point a
dedicated step type may be appropriate, with the format-specific
validation living in a containerized step rather than in strike's
controller.

### Distributed cache / shared state across runners

**What.** A cache layer that allows multiple strike runners to
share spec-hash-keyed artifacts without re-running steps.

**Why deferred.** Cache is an optimization, and optimizations
without a measured pain point are speculative. Strike's current
cache (per-runner OCI registry tags) works for single-runner
deployments. The right design for shared cache depends on the
trust model between runners (mutually trusting? mutually
distrusting? federated?), which is not yet specified.

**Revisit when.** A multi-runner deployment exists with a
specific trust model. The design then derives from that model;
attempting it now would produce a generic cache that fits no
specific case well.

### Cosign keyless signing (Fulcio + OIDC)

**What.** Signing without a long-lived private key, using a
short-lived certificate from Fulcio bound to an OIDC identity.

**Why deferred.** Strike currently signs with operator-supplied
ECDSA keys (per ADR-008). Keyless signing is the right answer for
deployments where the operator already has an OIDC workload
identity and prefers ephemeral keys; it is a worse answer for
deployments where the long-lived key is the trust anchor.
Supporting both adds code that has to be carried whether or not
it is used.

**Revisit when.** A consumer needs OIDC-backed signing
specifically. The integration is well-understood (cosign supports
it natively), and the asymmetric-identity principle (ADR-007)
already accommodates the mechanism: the *signer* is the OIDC
identity, the *trust anchor* is Fulcio's CA, and the two are
separate fields in the attestation.

## Consequences

- The list above is the known-deferred surface. Items not on the
  list and not in an ADR are decided by precedent: if the
  existing ADRs do not cover them, they require new ADRs.
- Each item has a "revisit when" trigger. The trigger is part of
  the deferral, not a vague intention. When the trigger fires, a
  dedicated ADR is written; this one is amended to mark the item
  as resolved with a reference.
- The list is a contract about *what strike does not do today*,
  not a roadmap of *what strike will do tomorrow*. Adding an
  item to this list does not commit strike to ever building it.
  Items can also be removed (e.g. "this is no longer a plausible
  direction") with an explanatory note.

## Principles

- Code is liability (deferred items are an explicit application:
  legitimate ideas held back because their cost has not yet been
  earned by a demand)
- External references are digest-pinned (when items are revisited,
  the new ADR will pin against the conditions that triggered the
  revisit, not against vague "best practices")
