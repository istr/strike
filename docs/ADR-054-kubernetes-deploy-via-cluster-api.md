# ADR-054: The kubernetes deploy is a control-plane API act

## Status

Accepted. Sharpens [ADR-051](ADR-051-deploy-as-sealing-point.md) D5, which
placed the kubernetes method in Layer V on the strength of its payload source
alone. Consistent with [ADR-039](ADR-039-deploy-step-as-attestation-root.md)
(deploy is the attestation root), [ADR-037](ADR-037-two-engine-trust-layers.md)
(the V/E layering), [ADR-007](ADR-007-asymmetric-identity.md) (client identity
and server identity are carried by different mechanisms), and
[ADR-029](ADR-029-peers-are-container-egress.md) (a peer declaration is a
container-egress contract). Makes a breaking lane-schema change; pre-beta, no
migration.

## Context

The kubernetes deploy method ran `kubectl` in a step container: the control
plane resolved a host kubeconfig, bind-mounted it at a fixed path, started a
hardened container from a lane-declared image, and piped its own standard input
into `kubectl apply -f -`. ADR-051 D5 kept the method in Layer V and named one
condition for it -- that the applied manifests come from `artifacts` rather than
from stdin, so the payload is control-plane-controlled.

That condition is necessary and not sufficient, and the reason is structural
rather than incidental. `ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md`
derives three corollaries about what a non-executing control plane can attest.
C1 states that completeness claims are never sound against a malicious engine,
because non-bypassability of a container's I/O is enforced by the engine. C2
states that intra-run content identity is not sound either, because the engine
materializes every handoff and can serve one byte sequence to the control
plane's verification read and a different one to the actual consumer. A
container-mediated apply falls under both: the manifests reach `kubectl` through
a mount the engine materializes, and the effect on the cluster is asserted by a
process the control plane does not observe. Fixing the payload source changes
where the bytes originate; it does not change who materializes them or who
performs the act.

The registry method does not have this problem, and ADR-051 D4 says why in one
sentence: the control plane owns the push and the engine never pushes. The
signed subject is the digest the control plane wrote through a transport it
dialed and verified itself. Nothing in that reasoning is specific to registries.
Applied to a cluster, it yields the same requirement.

ADR-051 D5 already applied this reasoning once, to a different method. It
removed `custom` because an arbitrary container action over an arbitrary
transport has no strike-controlled payload to sign and cannot satisfy D2 -- the
capsule records connection identity, not application effect. The kubectl path is
the same shape with a fixed command instead of an arbitrary one, and the fixed
command does not repair it.

## Decision

### D1 -- The apply is performed by the control plane against the cluster API

A kubernetes deploy dials the cluster API server from the control plane over a
trust-anchored TLS connection and applies the manifests through that connection.
There is no method container. The manifests are read by the control plane from
the deploy's digest-pinned `artifacts`, the same way the registry method reads
the payload it pushes.

This places the act in Layer V by the C3 construction rather than by assertion:
the dialed endpoint is verified against a declared anchor, the observed identity
is captured, and the payload is a value the control plane holds. What the
cluster does with an applied manifest afterwards remains outside strike's
sealing boundary and is evidenced by state recording (ADR-016), not by the
apply itself.

### D2 -- The kubectl implementation is removed; the method is suspended, not retired

The container-based implementation is removed from the tree. The method itself
is not: `kubernetes` remains in the deploy-method vocabulary, `#DeployKubernetes`
remains an arm of the deploy-method disjunction, and the Go-side union machinery
that dispatches on the discriminator remains in place. A lane that declares
`type: kubernetes` is rejected at lane validation with a not-implemented
diagnostic naming this ADR.

This is deliberately different from the `custom` removal. `custom` had no
Layer-V successor and its intended use survived as a different method entirely,
so removing its vocabulary entry was final. The kubernetes method has a
Layer-V form, described here, and that form reuses the discriminator, the
disjunction arm and the dispatch unchanged. Tearing down structure that returns
unchanged is churn, not simplification.

What does not return unchanged is removed with the implementation: the kubectl
container image reference, the host kubeconfig path, the deploy-strategy
vocabulary with its kubectl-verb projection, and the namespace field. The image
reference described a container that no longer exists. The kubeconfig bundled
the client credential and the server trust anchor into one file, which ADR-007
prohibits as a false-consolidated anchor. The strategy vocabulary named kubectl
subcommands, one of which (`rollout`) never formed a valid command line. The
namespace is the one field of the four that names an API concept rather than a
CLI one, and it falls for a different reason: a manifest carries its own
namespace, so whether a deploy-wide field belongs beside that -- and what it
means when the two disagree -- is part of the payload shape D5 leaves open. A
field whose role the governing ADR has not settled is exactly the dead schema
that invites an author to set something inert. `#DeployKubernetes` therefore
carries its discriminator and nothing else until the method is built.

### D3 -- Server trust is a method field; the client credential is carried separately

The cluster API server is a control-plane dial target, not container egress, so
it is declared as a field of the method in the shape ADR-051 D6 established for
the registry push destination -- an address plus a server-trust anchor -- and
not as an entry in the step's peer list, which ADR-029 reserves for container
egress.

The credential the control plane authenticates with is a separate declaration
from the anchor it verifies the server against (ADR-007). The two are never one
field and never one file.

### D4 -- What the rebuild owes

A kubernetes deploy, when built, produces the same evidence shape every deploy
produces (ADR-039, ADR-051 D2): the applied payload resolved from digest-pinned
`artifacts`; the declared-to-dialed-to-observed identity of the API server in
`Sealed.ObservedPeers`; the pre-state and post-state recording of ADR-016 as the
method's effect evidence (ADR-051 D7); and signed statements over a subject the
deploy names. Any deviation from that shape is a decision the rebuild ratifies
explicitly, not one it discovers.

### D5 -- What this ADR does not decide

The following are left open, because each depends on measurement against a
running cluster rather than on reading the design, and a ratified guess in an
append-only document costs an amendment to correct:

- the apply mechanism and whether a strategy vocabulary returns at all;
- how a manifest's kind is resolved to its API resource path;
- which credential mechanism carries the client identity;
- where the signed statements and any SBOM documents are published for a deploy
  that performs no registry push, and whether such a deploy declares a
  publication target of its own;
- the `artifacts` cardinality and arm composition for the method, which
  ADR-051 D9 left to the kubernetes rewiring and which this ADR leaves there;
- whether the state captures of ADR-016 stay container-computed (Layer E) once
  the apply itself is a Layer-V act, which is an ADR-016 question and not a
  kubernetes question.

## Consequences

- Removals: the kubernetes deploy execution path, the kubeconfig resolution and
  its host-filesystem access, the deploy-strategy type and its kubectl-verb
  projection, and the `image`, `namespace`, `kubeconfig` and `strategy` fields
  of the kubernetes method.
- Retentions: the deploy-method discriminator vocabulary, the two-arm
  disjunction, the discriminated-union interface, and the parse-time dispatch.
- Addition: one lane-validation rule rejecting the method, so the failure is
  structural and arrives at `strike validate` rather than mid-run.
- The registry method becomes the only executable deploy method for the beta
  line, and lanes that applied to a cluster restate their deploy step.
- Documentation that cites `kubectl` as the worked example of the no-subprocess
  invariant needs a different example; the invariant is unchanged and is in fact
  better served by a control-plane API call than by a container that runs a CLI.
- The attestation wire is untouched: no attest or trust-layer schema carries the
  deploy method or its strategy, so this change is not a freeze event.
- The rebuild is scheduled behind the beta line.

## Alternatives considered

- **Keep the container and source its manifests from `artifacts`.** This was the
  original shape of the rewiring, and it is what ADR-051 D5 literally asks for.
  Rejected: it satisfies the payload condition while leaving the act itself
  under C1 and C2, so the method would carry a Layer-V label for an effect the
  control plane neither performs nor observes. The label would be the defect.
- **Remove the kubernetes method entirely, as `custom` was removed.** Rejected:
  `custom` was removed because no Layer-V form of it exists. A Layer-V form of a
  kubernetes deploy does exist, and the structure it needs is the structure that
  is already there. Removing and re-adding the same discriminator, disjunction
  arm and dispatch is churn with a review cost and no benefit.
- **Adopt an upstream Kubernetes client library.** Rejected on the same ground
  the Rekor client was rejected on: the generated request and response types are
  worth importing, an entire client stack and its transitive dependency cluster
  is not. The dependency surface is the supply-chain surface.
- **Leave the broken implementation in place until the replacement lands.**
  Rejected: it would ship a method whose own governing ADR describes it as
  unsound, and a lane author has no way to see that from the schema. A
  validation-time rejection states the same fact where the author reads it.

## Principles

- **Runtime is attested.** A deploy attests an act the control plane performs
  and observes; an effect asserted by a container is engine-dependent evidence
  and cannot carry a Layer-V claim.
- **Identity is asymmetric.** The credential the control plane presents to the
  cluster and the anchor it verifies the cluster against are separate
  declarations; the kubeconfig that bundled them is removed rather than
  re-typed.
- **Peers are declared.** The cluster API server is a declared endpoint with an
  explicit trust anchor, carried where control-plane dial targets are carried
  rather than in the container-egress peer list.
- **Enforcement is structural, not discretionary.** The suspension is a
  validation rule, not a documented caveat; a lane that declares the method
  fails to validate.
- **Code is liability.** The unsound implementation is deleted rather than
  repaired, and the structure that returns unchanged is kept rather than removed
  and rebuilt.
