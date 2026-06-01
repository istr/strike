# ADR-037: Two Trust Layers Toward the Container Engine

## Status

Accepted. This sharpens an earlier draft, which is kept for history; the
argument is reorganized around the kind of failure each layer is vulnerable to,
but the decisions are continuous with the first version.

Refines, and does not supersede, [ADR-001](ADR-001-engine-via-api-not-exec.md).
Reframes the trust statements in
[ADR-005](ADR-005-per-step-security-profile.md),
[ADR-006](ADR-006-typed-secrets.md),
[ADR-012](ADR-012-engine-identity-capture.md),
[ADR-028](ADR-028-step-container-egress-mediation.md), and
[ADR-033](ADR-033-ssh-peer-egress-and-unified-mediation.md). Its scope statement
(D4) is the revisable crux. Extended by ADR-040 (control-plane SBOM generation and keyless attestation),
which realizes the V and E layers as a standard SLSA provenance predicate and a
co-attached engine-context predicate.

## Context

ADR-001 flies a single banner: the container engine is an untrusted worker. "The
controller signs only digests it has independently verified. Engine self-reports
are not trusted." That banner is exactly right for one class of guarantee and
silently wrong for another, and the difference is best named not by what the
mechanism does but by **the kind of lie each guarantee is exposed to**:

- Some guarantees are produced by the controller, either by independent
  re-verification or by strike being the observer. A malicious engine cannot
  make strike emit a **false positive** here: it cannot get a claim signed that
  strike did not itself verify or observe. An attempt is caught.
- Other guarantees depend on the engine applying a configuration strike sent. A
  malicious engine simply does not apply it, and the result is a **silent false
  negative**: something happened (egress that bypassed the mediation, a profile
  that was not enforced) that the attestation does not, and cannot, record. No
  false claim is made, but the picture is incomplete.

The conflation of the two was harmless while the controller and the engine
shared a host, because everything in the first class happened in the controller
by default. The redesign of SSH egress mediation forced the distinction into the
open in two ways. It moves the *production* of positive observations (peer
identity capture) and, in a remote topology, the signing context, toward the
engine, so the question "does this still hold against a dishonest engine"
becomes concrete. And it crystallized exactly what strike does and does not
promise about egress: it notarizes the traffic that passes through it and
excludes false positives within that traffic; it does not promise that the
mediated traffic was the run's exhaustive activity.

This ADR names the line, organized around that failure-mode distinction. It
records no topology decision; it is the predicate those decisions must satisfy.

## Decision

### D1: Two layers, named by their failure mode

Every existing guarantee, and every future mechanism, belongs to exactly one
layer.

**Layer V -- verify or observe; the no-false-positive layer.** Assured by
independent re-verification, content addressing, reproducibility, or by strike
being the direct observer. A fully malicious engine cannot forge these past the
verification, or cannot inject them at all because strike produced them itself.
The adversarial failure this layer is built to exclude is a false positive.
Members:

- **Input reference integrity.** Each OCI image, git commit, and upstream file
  is digest-pinned; the controller recomputes the content hash and matches the
  declared pin. A lying engine, a MITM, and a hostile registry fail the same
  check (ADR-001, ADR-011).
- **Reproducibility.** Byte-identical inputs yield byte-identical outputs;
  ADR-009 proves it by stage-2 / stage-3 equality. This is what makes output
  integrity engine-independent (see D3 for the precise sense).
- **Schema validity.** Inputs and outputs validate controller-side against the
  CUE that generates the Go types.
- **Positive attestation observations, while produced in the controller.** The
  DoT resolver's TLS identity and each peer's upstream TLS or SSH identity,
  captured because the controller establishes those connections itself.
- **Controller secret custody, while the controller runs on trusted ground.**
  The attestation signing key lives in the controller and is never sent to the
  engine (ADR-008).

**Layer E -- enforce; the completeness layer.** Assured by the engine applying a
configuration strike sends. Engine-dependent. The adversarial failure is a
silent false negative: the engine omits the enforcement and nothing records the
omission. Members:

- **Per-step security profile:** cap-drop, read-only rootfs, no-new-privileges,
  userns (ADR-005).
- **Egress restriction.** The boundary is the network topology, not the
  redirection. Redirection mechanisms (DoT-answer steering of container traffic,
  proxy
  environment variables) are cooperative: they route an honest client but do not
  bind a hostile one. Only the topology (an internal network with no route
  except via the capsule) enforces, and the topology is applied by the engine.
- **Step-secret confidentiality against the engine.** Typed secrets reach step
  containers through the engine's container-create request body (ADR-006). The
  engine is the delivery channel and therefore reads them. The typed-secret
  discipline prevents leakage through strike's own logs, serialization,
  arguments, and disk; it cannot hide the secret from the engine that delivers
  it.

### D2: The promise is the exclusion of false positives, not completeness

This is the load-bearing decision and the one the SSH work sharpened.

- strike notarizes only what passes through it as control or mediation plane.
  Within that traffic it excludes false positives: a positive claim (peer
  identity, input digest, resolver identity) is signed only after independent
  verification or direct observation against a declared trust anchor.
- strike does **not** promise that the mediated set was the run's exhaustive
  activity. Traffic a compromised host routes around the mediation is a false
  negative, invisible to the attestation, and out of scope by design. This is
  not a weakness to be apologized for; it is the honest boundary, and it is
  coherent only because completeness is a Layer-E property strike does not claim
  against a dishonest engine (D4).
- Therefore the attestation must be **self-describing about its scope.** It
  records "these peers and inputs were mediated and verified"; it must not be
  structurally misreadable as "this was the complete egress" or "the build was
  confined". A verifier reading the attestation offline must be able to tell a
  verified positive claim from a completeness claim, because strike makes the
  former and not the latter. This is a constraint on the attestation predicate
  and on `strike verify`, not merely documentation: the predicate carries an
  explicit "mediated, not exhaustive" marker.
- **Corollary: selection is not trust.** Routing and selection mechanisms (DNS
  answers, host ports, per-connection capability tokens) are never trust
  anchors. A selector decides *what gets verified*; it never substitutes for the
  verification. Trust is always the independent check or the TCB observation.
- Excluding false positives within mediated traffic reduces to the correctness
  of the anchor checks, which is exactly what differential cross-validation (the
  golden vectors, the second implementation) defends. The residual soft spot is
  the `system_ca` / `system` trust opt-ins, where the strength of "no false
  positive" is only as good as the OS trust store.

**The predicate distinguishes provenance structurally, not by per-field tag.**
Every recorded fact has one of four provenances, and a verifier must be able to
tell which from the predicate alone:

- **Declared** -- from the signed lane (`lane_ref`): which steps declare which
  peers and inputs. Layer V.
- **Observed** -- the controller verified or directly observed it: the resolver's
  channel identity, an input's digest, a peer's connection identity validated
  against the declared anchor. Layer V.
- **Engine-asserted** -- a runtime fact whose binding rests on the engine: above
  all, the attribution of a runtime network action to a specific step, which
  rests on the engine routing the right container's traffic and provisioning the
  right container (the same fact that makes step secrets engine-readable, ADR-006,
  and that the front-step-demux spike confirmed has no control-plane-independent
  basis). Layer E.
- **Informational** -- recorded for audit, relied upon for nothing: the engine
  identity record. The engine is untrusted, so neither its observed cert
  fingerprint nor its self-reported version/rootless is a trust input.

The governing rule, in preference to explicit per-field trust tags (which are
overengineered for this): **no predicate record may mix provenances unmarked.**
A record that mixes is split; a record that is pure carries its provenance by its
structural position and name, not by a tag. This is how the "self-describing
scope" requirement above is met structurally rather than through out-of-band
documentation.

Two consequences for the current predicate, both pre-existing and independent of
any egress redesign:

- The `#EngineRecord` today mixes a controller-*observed* field (its cert
  fingerprint) with engine-*self-reported* fields (version, rootless) in one
  unmarked record. Under the rule it is marked **informational** wholesale (it is
  not a trust input either way, the engine being untrusted), resolving what an
  earlier draft left open as "does the engine record need a third category": yes,
  the informational one.
- Per-step *attribution of provenance records* is deliberately **not serialized**.
  The step that consumed an input is reconstructable from the signed lane if ever
  needed, carries no usable attestation information on its own, and would only add
  noise when steps share identical inputs. The provenance array stays flat; this
  is a decision, not an omission.

### D3: Output integrity is engine-independent post-hoc, not intra-run

For *inputs*, the digest check is intra-run and hard: a mismatch is refused
before the DAG proceeds. For *outputs*, what the controller signs is the digest
of the bytes the engine returned; the controller has no intra-run oracle for
"what a correct build should have produced". The engine-independence of output
integrity therefore comes from reproducibility plus an independent rebuild (the
second-implementation story), which is an ecosystem property exercised after the
fact, not a check strike performs at signing time. A malicious engine can make
strike sign a subtly wrong artifact; the fraud is detectable only when someone
rebuilds and the digests diverge. This is the intended guarantee, but it is
weaker than "strike catches it", and no mechanism may claim more than this.

### D4: Engine threat scope (the revisable crux)

The documented threat model (ADR-028) enumerates compromised *step containers*:
malicious dependencies, forged binaries, prompt-injected LLM code, RCE under
hostile input. A maliciously-behaving engine *daemon* is not in that
enumeration.

This ADR makes the omission explicit: **the engine daemon and its host are
trusted for Layer E; strike's defense is against compromised step containers,
not against a compromised engine.** Layer V holds regardless, because it does
not depend on engine honesty. Layer E holds only under this scope. The "notarize
the mediated traffic, do not promise completeness" posture of D2 is the direct
expression of this: strike does not even attempt to defend completeness against
a dishonest engine, so the honest promise is the false-positive exclusion, which
is engine-independent.

This is the description of today's reality and the single decision the operator
should consciously ratify or widen. Widening it -- defending Layer E against a
malicious engine -- is not a configuration change; it requires either
confidential computing with remote attestation of the engine host, or accepting
that Layer E guarantees degrade to "declared, not enforced" against that
adversary. No middle option exists.

### D5: Invariant for topology changes

Any future mechanism that moves the *production* of a Layer-V guarantee, or the
*capability to use* it, onto, behind, or inside the engine converts it from
engine-independent to engine-dependent, and is admissible only if one of the
following holds:

1. **Compensated so the guarantee stays engine-independent.** For the signing
   key: it never comes to rest on, or becomes usable by, the engine; it is held
   by an external authority (KMS, OIDC workload identity, keyless / Fulcio) and
   strike requests signatures without holding durable key material. For observed
   identities: either the controller keeps observing directly, or a
   controller-side cross-check re-establishes the observation.
2. **Verifiable by remote attestation.** The engine host runs the component in a
   TEE whose image identity and memory protection are remotely attested.
3. **Scope explicitly widened.** D4 is consciously changed and SECURITY.md
   records the widened assumption.

A mechanism satisfying none of these is rejected: it would silently relabel an
engine-independent guarantee as engine-dependent while still presenting it as
the former, the exact conflation this ADR exists to prevent.

**Worked example (the invariant has teeth).** ADR-025 forwarded the host
ssh-agent socket *into* the step container. The key material never moved; by a
naive "where do the bytes rest" reading, nothing was wrong. But the *capability*
to use the key was delegated into untrusted space: a hostile container could
authenticate arbitrary SSH and request signatures over chosen blobs with the
host key, bounded only by egress. That is a Layer-V guarantee (client identity
usable only by the controller) defeated without any key byte leaving its agent.
A subsequent SSH-egress redesign restores it by clause 1: the agent terminates
in the capsule, the container holds no usable capability, and the key is
exercised only by strike for the specific attested operation. The invariant is
about the capability to produce or use a guarantee, not only about where bytes
sit.

**Ordering corollary.** Exposing an inbound endpoint on the control plane (which
a remote-engine egress proxy requires) is itself a reason to
satisfy clause 1 first: a network-reachable process that holds a durable signing
key is a larger target than an outbound-only one. Externalize the key, then
expose the plane.

## Consequences

- **SECURITY.md and the trust-boundary diagram are relabeled** into the
  failure-mode framing: Layer V excludes false positives and is
  engine-independent; Layer E provides completeness, is enforced by an engine
  trusted for that purpose under D4, and fails as a silent false negative.
  ADR-012's self-reported engine record is reclassified explicitly as
  informational context, belonging to neither layer.
- **The attestation predicate gains a scope marker and a provenance discipline**
  (D2): the "mediated, not exhaustive" marker, plus the rule that no record mixes
  trust provenances unmarked. These are the concrete schema obligations this ADR
  creates; they land when the attestation predicate is next touched and are
  `strike verify` inputs. Everything else in this ADR is classification.
- **A small, separable predicate-hardening task falls out, independent of any
  egress work:** mark `#EngineRecord` informational (it currently mixes an
  observed cert fingerprint with self-reported version/rootless, unmarked). This
  may be slotted before the egress work since it is self-contained. The
  provenance step-key is deliberately left unserialized (D2) and needs no change.
- **Downstream egress-mediation work inherits a concrete admissibility test (D5)
  and a scope discipline (D2)** instead of an open argument. The motivating case
  is a step-container egress redesign that moves identity production and
  credential custody toward the engine: under D5 it is admissible only with the
  signing/credential authority externalized (clause 1), and under D2 it notarizes
  only mediated traffic with a self-describing scope. When that work adds per-peer
  connection records, each splits into an observed peer identity (Layer V) and an
  engine-asserted step attribution (Layer E) per the no-mixing rule.
- **The host-local couplings are reframed, not condemned.** Forwarded sockets
  and bind-mounted anchors are Layer-E delivery mechanisms whose host-locality
  is an engineering limitation, not a trust property; replacing a bind mount
  with an in-band transport does not change which layer a guarantee sits in.

## Open points for revision

- **D4 scope ratification.** Confirm or widen "malicious engine daemon out of
  scope". Everything downstream hangs on this.
- **The CUE form of the D2 marker and provenance discipline.** How "mediated, not
  exhaustive" and the four provenances are expressed in the schema and surfaced by
  `strike verify`. The discipline is decided (structural, no per-field tags); only
  its concrete expression is open.
- **Layer membership of the resolver and mediator observations** once a topology
  is chosen: Layer V only while produced in the controller. A sidecar or
  embedded design moves them and must invoke a D5 clause.
- **Naming.** "Layer V / Layer E" is placeholder vocabulary; the failure-mode
  framing suggests alternatives ("no-false-positive layer" / "completeness
  layer") that may read better in SECURITY.md.

## Principles

- Runtime is attested (the ADR fixes what the attestation can and cannot prove,
  and requires it to say so).
- Identity is asymmetric (the capability-externalization invariant of D5 is the
  same shape as client-identity delegation, ADR-007 / ADR-025).
- Code is liability (the ADR adds one schema obligation and prevents mislabeled
  mechanisms; it introduces no mechanism of its own).
- Reproducibility is enforced (the load-bearing Layer-V guarantee for output
  integrity, D3).
- **Enforcement is structural, not discretionary** (the layer a guarantee sits
  in is a property of its mechanism, not a per-lane choice).
