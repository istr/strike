# ADR-039: The Deploy Step as Attestation Root

## Status

Accepted. Codifies decisions ratified in design discussion. Refines but does
not supersede [ADR-037](ADR-037-two-engine-trust-layers.md) (trust layers),
[ADR-038](ADR-038-protocol-mediated-ssh.md) (mediated connections),
[ADR-016](ADR-016-drift-recording-posture.md) (drift recording),
[ADR-022](ADR-022-network-opt-in-as-peer-list.md) (peer declaration),
[ADR-028](ADR-028-step-container-egress-mediation.md) (egress mediation). Shares
its structural reasoning with [ADR-011](ADR-011-sources-elimination.md).

## Context

strike's value is the attestation: the signed account of what was built, from
what pinned inputs, by what runtime, and where it was deployed. The deploy
attestation is where that trust chain is sealed and signed (ADR-037).

Attestation assembly follows a produce-then-collect model. The executor runs the
steps (possibly in parallel); each step leaves attestation information in
strike's internal state as it completes (artifacts, provenance, the network
records of its capsule). There is no attest-then-deploy interleaving: the
attestation record for a deploy is assembled once the work it accounts for has
terminated, by collecting that already-produced information. Today the assembly
runs per deploy step and collects the deploy step's transitive DAG predecessor
closure (its "sub-tree") via the same walkers used for declared peers and
provenance.

Two properties this model depends on were implicit and unenforced:

1. **A lane could contain zero deploy steps.** strike would run, produce
   artifacts, and attest nothing to any target. For a tool whose entire value is
   the attestation, that is a degenerate outcome: work performed, nothing
   sealed.

2. **Deploy steps were endpoints only by convention.** A deploy step declares no
   output in every lane written to date, so nothing references it and it lands
   last in topological order. But the schema does not forbid a deploy step from
   declaring an output. If one did, a later step could depend on it, and the
   deploy step would no longer be the complete and final account of what it
   deployed: work downstream of the deploy could still alter the deployed result
   after the deploy's attestation was assembled.

A third consideration shapes the model. A lane may deploy to more than one
target (for example staging and production, or several registries). Each target
is a distinct deploy step. An attestation scoped to one deploy step's sub-tree
is a precise account of that one deployment; a single lane-wide attestation
would conflate the independent branches of separate deploys into one
undifferentiated record.

The framing that unifies these is that a deploy is any terminal act that
publishes or applies a pinned artifact: a registry push (`method: registry`), a
Kubernetes apply (`method: kubernetes`), or a custom container action
(`method: custom`). A build-and-push pipeline is a deploy whose target is a
registry. strike is, in effect, a digest-pinned multi-stage build whose terminal
act is an attested deploy. Pre-state capture may itself read a digest-pinned
prior image, yielding drift signaling (ADR-016) against a known prior version.

## Decision

**D1. Every lane must contain at least one deploy step.** `lane.Parse` /
`lane.Build` reject a lane with no deploy step. A lane that produces artifacts
but deploys nowhere has no attestation to produce and is not a valid strike
lane; the act of publishing those artifacts (a registry push) is itself a deploy
step.

**D2. A deploy step has no output.** The lane schema forbids `outputs` on a
deploy step, and `lane.Build` rejects any dependency edge whose target is a
deploy step. Deploy steps are therefore DAG leaves by enforcement, not by
convention.

**D3. The attestation is produced per deploy step, scoped to that step's
transitive DAG sub-tree.** The sub-tree is the deploy step together with all its
transitive predecessors. A lane with N deploy steps produces N attestations,
each scoped to its own branch and each independently offline-verifiable. The
per-deploy-step collection covers, for that sub-tree: the produced artifacts and
their pinned content, declared peers, observed peers, provenance records, and
the deploy target with its pre- and post-state digests.

**D4. The deploy step's own peers appear in the attestation under layer V, both
declared and observed.** This includes the deploy method's peers and the peers
of the pre- and post-state capture containers. Declared peers (the method's and
the captures') are recorded in `sealed.peers`; the connections strike observed
and validated against those anchors are recorded in `sealed.observed_peers`. No
declared peer that strike acted on is omitted from the attestation, and the
observed set is always a subset of the declared set.

**D5. Every DAG leaf is a deploy step.** A leaf -- a step no other step
depends on -- must be a deploy step. `dag.ValidateLeavesAreDeploys` rejects any
non-deploy leaf. A non-deploy step whose output nothing consumes is a dangling
terminal build: it produces an artifact that is neither used nor deployed, so
it contributes to no attestation. The rule also has an execution-semantics
basis: a step's failure can only stop its successors, so a leaf can stop
nothing. A check or QA step meant to prevent a deploy must therefore be a
*predecessor* of that deploy, not a leaf -- it consumes the artifact and
produces an output the deploy consumes (the validated artifact, or a report the
deploy takes as an input), so its failure stops the deploy and the attestation
records that what was deployed is what passed the gate. Together with D2 (a
deploy step is a leaf), D5 makes "leaf" and "deploy step" coextensive: a lane's
leaves are exactly its deploy targets. D5 also subsumes D1 for any non-empty
acyclic lane (every finite DAG has a leaf, and that leaf must be a deploy), but
D1 is retained for its clearer early diagnostic.

Unlike D1 and D2, D5 is enforced only in Go, not in the schema. The invariant
is a property of the resolved edge relation between steps; expressing it in CUE
would re-derive that relation from the `from` references by hand -- duplicating
the Go edge resolvers and producing worse diagnostics -- so the Go check is the
binding contract and the schema records only the intent. This is the same
"semantically schema, technically Go" split used for the IP-literal resolver
check (ADR-024). Because the check needs the built graph, it runs after
`lane.Build` rather than inside it: `Build` stays usable for graph-mechanism
unit tests on partial graphs, while the CLI runs D5 as part of a single
validation gate -- `strike validate`, `strike dag`, and `strike run` all reject
a non-conforming lane identically, with one error and no other output.

## Consequences

- Every lane terminates in at least one signed attestation. The no-deploy
  degenerate case is gone.
- A lane's leaves are exactly its deploy targets (D2 + D5). A dangling non-
  deploy build, or a check step that produces nothing and so cannot gate a
  deploy, is rejected at validation rather than silently performing work that
  is never attested.
- A deploy step's sub-tree is provably complete and final when the deploy step
  runs: topological order guarantees every predecessor has terminated, and the
  leaf invariant (D2) guarantees nothing downstream can alter what was deployed.
  The per-deploy-step attestation is therefore a sound, closed account of its
  branch.
- Multiple deploy targets are supported with no additional mechanism: each is a
  deploy step, each yields its own branch-scoped attestation. A verifier asking
  "what is the provenance of what was deployed to production" reads the
  production deploy step's attestation, undiluted by other branches. Predecessor
  records shared across branches appear in each attestation that depends on them,
  which is correct: each attestation must stand alone for offline verification.
- Within each attestation, declared peers are a superset of observed peers, so a
  verifier cross-checking observed against declared never sees an observed peer
  that was not declared (which would otherwise read as a false indicator of
  compromise).
- The model is in line with the current per-deploy-step implementation; it
  enforces invariants the implementation already assumed, rather than
  restructuring how or when attestations are assembled.
- The breadth of "deploy" must be documented for operators: a deploy is not only
  a Kubernetes apply but any terminal publish or apply of a pinned artifact,
  including a registry push.
- Migration: lanes with no deploy step (build-only lanes) become invalid.
  Test fixtures are swept accordingly. Pre-beta, so no migration notice is
  required.
- This is the foundation on which observed-peer population (ADR-038) is built:
  each deploy step collects the observed connection records of its sub-tree,
  mirroring the existing declared-peer and provenance collection.

## Trust layering (relationship to ADR-037)

The trust-layer split is unchanged. The deploy method's peers and the
state-capture peers enter layer V because strike's control plane dials and
validates them against the declared anchor itself; the engine is not in that
validation path, so the claim is sound without engine trust. Per-step
attribution of a connection to a step remains layer E (engine-asserted), as
established in ADR-037 D2 and recorded in `engine_dependent.peer_attribution`.
This ADR does not move any claim across the V / E boundary; it only states that
the deploy step's own declared and observed peers are collected into V alongside
those of its predecessors.

## Alternatives considered

- **One run-level attestation per lane, with a list of deploy targets.**
  Rejected. With multiple targets it conflates the independent sub-trees of
  separate deploys into a single undifferentiated record, losing the per-deploy
  precision that a verifier needs ("what exactly went to production"). The
  per-deploy-step sub-tree scope is strictly more precise, and it matches the
  existing implementation.

- **Optional deploy step, with an attestation carrying an empty deploy-target
  section when none is present.** Rejected. It preserves the degenerate case
  (strike attesting nothing to any target) that D1 exists to remove, and it
  provides no use that a registry-push deploy step does not already serve.

- **Explicit two-phase execution: run all non-deploy steps, then all deploy
  steps.** Rejected as unnecessary. Topological order together with the leaf
  invariant (D2) already guarantees that a deploy step's sub-tree has terminated
  when the deploy step runs. An explicit phase split would add legibility but no
  correctness, at the cost of restructuring the executor traversal; not worth it.

## Principles

- **Code is liability.** The decision reuses the existing per-deploy-step
  assembly and the existing sub-tree walkers; it adds enforcement of two
  invariants, not a new lane-wide assembler.
- **CUE first.** D1 and D2 are enforced in the schema (and in `Build`), not by
  runtime convention. D5 is the deliberate exception: it is a graph-edge
  invariant enforced only in Go, after `Build`, because re-deriving the edge
  relation in CUE would merely duplicate the Go resolvers (the same
  "semantically schema, technically Go" split as ADR-024).
- **Reproducibility is enforced.** A branch-scoped attestation is a
  deterministic function of its sub-tree, independent of unrelated branches and
  of execution interleaving.
