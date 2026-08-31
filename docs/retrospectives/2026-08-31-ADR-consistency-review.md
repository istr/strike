# ADR Consistency Review -- istr/strike

| | |
|---|---|
| Repository | `istr/strike` |
| Commit (pinned) | `85523afecd6b04e239affbf44a00df65b146b73b` |
| Corpus | `docs/ADR-001` ... `docs/ADR-054` + `docs/ADR-INDEX.md` (55 files, 468,520 bytes, read in full) |
| Information basis | ADR text only. No code, no roadmap, no git history, no other documents were consulted. |
| Review date | 2026-08-31 |

## 1. Scope and method

All 55 `docs/ADR-*` files at the pinned commit were read completely (byte-count-verified,
lossless). The review checks the **internal consistency of the ADR corpus** under the
working rule "the newer decision wins because it rests on better information". A finding
is raised when that rule cannot be applied from the corpus alone: when a superseded
statement carries no marker, when two amendment notes compose into a contradiction, when
a reference points at text that does not exist, or when a decision's disposition is left
genuinely open.

Findings are grouped into three classes:

* **C -- Contradictions.** Two ADR statements conflict in substance, and the corpus does
  not resolve the conflict via a marker on the older text.
* **A -- Ambiguities.** The corpus leaves a decision-relevant question open, or vocabulary
  drifts without a recorded rename.
* **R -- Reference and status hygiene.** Broken links, dangling references, and gaps in
  the status/amendment conventions of `ADR-INDEX.md`.

Each finding names a proposed **fix type** from the agreed taxonomy:

* **AMENDMENT** -- an append-only addition (header blockquote or dated amendment section)
  on the older ADR, referencing the newer one.
* **REFERENCE** -- a reference repair (link target or referent correction), editorial in
  nature, decision content untouched.
* **OBSOLESCENCE WITH REFERENCE** -- a status change ("Superseded [in part] by ADR-NNN")
  plus a note pointing at the superseding record, mirrored in `ADR-INDEX.md`.

Severity is rated by **planning impact**: High = a planner reading the corpus is actively
misled; Medium = a careful planner can reconstruct the truth but only via cross-reading;
Low = cosmetic or localized.

Concrete correction texts are delivered separately, one finding per turn, in the house
amendment style documented in section 8.

## 2. Summary

The corpus is, on the whole, well maintained: partial supersessions of ADR-008, -013,
-016, -017, -019, -022, -023, -026, -035, and -036 all carry the expected notes, and
ADR-030/-044/-046/-049/-051 demonstrate a disciplined append-only amendment practice.
The problems concentrate in four clusters:

1. **The ADR-038 supersession was never propagated.** ADR-038 replaces the entire SSH
   mechanism of ADR-024/-025 and the SSH portions of ADR-028/-033, yet none of the four
   carries a marker and the index lists all of them as plain "Accepted" (C-01). This is
   the single largest source of planning confusion.
2. **The deploy rework (ADR-051/-054) invalidated older statements without markers** --
   push-connection recording in ADR-030 (C-02), the cache-publish mechanism in ADR-026
   (C-08), the Kubernetes-as-HTTPS-peer rule in ADR-022 (C-07), and parts of ADR-039
   (A-05).
3. **Two amendment notes inside ADR-013 compose into a contradiction**, and the Rekor
   failure semantics have no stated successor for the Rekor-v2 path (C-03).
4. **Reference hygiene**: eight broken link filenames across ADR-028/-033/-037 (R-01),
   two mis-attributed references (R-02, R-03), one phantom reference (R-04), and an
   index whose status vocabulary cannot express what the corpus actually does (R-06).

Totals: 12 contradictions, 8 ambiguities, 7 hygiene findings.

## 3. Findings -- Contradictions

### C-01 -- ADR-038's supersession of the SSH mechanism is unmarked on all four affected ADRs

**Severity: High. Fix type: OBSOLESCENCE WITH REFERENCE (ADR-024, ADR-025) + AMENDMENT (ADR-028, ADR-033) + index update.**

ADR-038 states in its Status: "Supersedes the SSH handling of ADR-024 (container-mounted
`known_hosts`), ADR-025 (agent socket forwarded into the container), and the SSH portions
of ADR-028 / ADR-033 (raw TCP-forward relay, per-peer host-port mux)." It reverses both
older mechanisms outright: the real peer's `known_hosts` is no longer mounted into the
container (D3), the in-container agent socket is removed, and "the ADR-025 fail-fast on a
missing agent inverts" (D3).

Yet:

* ADR-024 and ADR-025 carry **no amendment note at all**; their Status is plain
  "Accepted", and their Decision sections still instruct the exact mechanisms ADR-038
  removed (bind-mounted `known_hosts` at `/etc/ssh/ssh_known_hosts`; proxy agent socket
  at `/run/strike/ssh-agent.sock`; fail-fast on missing `SSH_AUTH_SOCK`).
* ADR-028's amendment chain ends at ADR-033 ("Completed by ADR-033 ... SSH through
  per-peer raw-TCP forwards") -- a description ADR-038 then replaced with the run-level
  front. No ADR-038 marker exists on ADR-028.
* ADR-033 defines D27 (per-peer port-mux) and D28, both of whose SSH mechanics ADR-038
  supersedes; ADR-033 carries no forward marker.
* `ADR-INDEX.md` lists 024, 025, 028, and 033 as "Accepted" with no qualification,
  although the index's own header promises "the older ADR's status changes to
  `Superseded by ADR-NNN`".

**Worked symptom** (why this bites planning): ADR-033's Consequences state "The deploy
paths (state capture, Kubernetes, custom) gain the same mediation as run steps",
including SSH; ADR-051 D5 states "the deploy path continues to reject SSH peers until
that front lands". These are reconcilable only for a reader who already knows ADR-038
superseded ADR-033's SSH mechanism -- which no marker on ADR-033 says.

Also folded here: stale mechanism parentheticals downstream of the same supersession --
ADR-029's Decision ("SSH (known_hosts + agent proxy)") and ADR-028's threat-model bullet
"must not resolve DNS names not on the declared peers list", which ADR-038 D4 relaxes to
lane-level resolution ("a minor DNS-visibility leak"). One note per file can carry these.

### C-02 -- Push-connection recording: ADR-030 forbids what ADR-051/ADR-052/ADR-016-amendment now do

**Severity: High. Fix type: AMENDMENT on ADR-030 (dated, partial obsolescence of the push row, with reference).**

ADR-030 decides, for OCI push: "no trust declaration and no identity recording", on two
grounds -- the registry identity contributes nothing to trust, and it "is not even
observable by the controller" because the engine performs the transfer. ADR-051 D4
changed the actor: "The control plane owns the push; the engine never pushes"
(remote.Write), which removes the observability premise. Consistently with that, ADR-051
D10 places the push destination among the observed peers ("a registry deploy carries its
push destination and the resulting pushed digest"), the ADR-051 amendment on ADR-016
names `sealed.pushed` (registry authority, repository, manifest digest) as a pairing
surface, and ADR-052 D5 lists "push-connection identity" as a first-wins capture.

The push row of ADR-030's connection table is therefore superseded in substance, with no
marker on ADR-030. The pull row stands (ADR-040 D4: "The engine may still pull by digest
for now"), so the fix must be scoped to the push side only -- ADR-030's general principle
("recording follows the trust chain") survives; it is the classification of the push
connection that changed when the actor changed.

### C-03 -- ADR-013: the two supersession notes compose into a contradiction; Rekor-v2 failure semantics are unowned

**Severity: High. Fix type: AMENDMENT on ADR-013 (reconciling addendum with references to ADR-040/ADR-043; optionally OBSOLESCENCE WITH REFERENCE for the v1-bound clauses).**

ADR-013 carries two partial-supersession notes written at different times:

* The "Superseded in part" section (ADR-040 D3) says the strike-specific payload type
  "remains **only** on the internal collect-model envelope (`SignAttestation`), whose
  disposition is ADR-040 instruction 3b".
* The newer header note (ADR-043) retires "the `SignAttestation` collect-model envelope".

Composed, the payload type `application/vnd.strike.attestation+json` remains nowhere --
but the older note still asserts it "remains", and the reader must perform the
composition unaided. A one-paragraph reconciliation is missing.

Second, unowned disposition: ADR-013's Rekor failure semantics -- SET verification
mandatory/fail-closed, transient failures fail-open, >100 KB envelopes skipped -- are
Rekor-v1-bound. ADR-043 retires the v1 client; ADR-053 establishes that Rekor v2 signs
no time and has no SET. No ADR states which failure semantics govern the v2 submission
path (fail-open on unavailability? size limits?). ADR-040/-041 do not restate them. This
is a genuine decision gap, not just a stale sentence.

### C-04 -- ADR-021's deferred items were overtaken without the amendment its own protocol requires

**Severity: High. Fix type: AMENDMENT on ADR-021 (per-item resolution notes with references).**

ADR-021's Consequences bind the record: "When the trigger fires, a dedicated ADR is
written; this one is amended to mark the item as resolved with a reference." That never
happened for:

* **"Cosign keyless signing (Fulcio + OIDC)"** -- resolved by ADR-040 (keyless is the
  model) and ADR-043 (keyed signing retired). ADR-021 still asserts "Strike currently
  signs with operator-supplied ECDSA keys (per ADR-008)", which is now false and
  contradicts two accepted ADRs.
* **"Distributed cache / shared state across runners"** -- partially addressed by ADR-026
  (remote-cache push/pull; ADR-026 itself defers only "multi-machine cache federation
  beyond the basic push/pull pattern"). Note the interaction with C-08 before wording
  this item's resolution.
* **"System CA opt-in for HTTPS peers"** -- see A-04; the item's state is contradicted by
  ADR-037/ADR-041 phrasing.

The other items (additional engines; microVM steps; output verification) remain
correctly deferred.

### C-05 -- ADR-004's "Go types are generated from CUE, not hand-written" vs. the settled hand-mirrored attest types

**Severity: Medium. Fix type: AMENDMENT on ADR-004 (record the exception with references).**

ADR-004's Decision is absolute: "Go types are generated from CUE, not hand-written."
Later records settle the opposite for the attestation predicate: ADR-042 ("the deploy
predicate's Go types are hand-mirrored rather than generated ... the types stay
hand-written") and ADR-047 section (3)/(6) (the `attest` package is "hand-written and validated
against CUE at runtime, not gengotypes-generated"). The ADR-048 amendment converts only
the artifact/SBOM `record` package back to generation. ADR-004 carries no note, so a
reader of the foundational schema ADR is told a rule the corpus has knowingly narrowed.

### C-06 -- Tier lattice: ADR-048 section 5 and its diagram contradict ADR-044's later amendments

**Severity: High. Fix type: AMENDMENT on ADR-048 (defer lattice authority to ADR-044's amendments, with reference).**

ADR-048 section 5 adds the concept tier "between foundation and transport", says "A concept
package depends only on the `primitive` foundation package", and its diagram folds
primitive into foundation ("foundation -- primitive (irreducible types) + the existing
logic-free utilities"). ADR-044's amendments of 2026-06-26 -- which state they realize
"the precise dependency target the concept tier (ADR-048) builds on", i.e. they refine
ADR-048 -- decide differently: `internal/primitive` is "carved out of foundation into its
own component"; the concept tier "sits between **primitive** and transport"; and
`concept.mayDependOn` is `[primitive]`, "never from foundation utilities". Under ADR-044,
primitive is not a foundation package and concept does not depend on foundation at all.

The enforcement-anchored ADR-044 amendments are the later, more precise record; ADR-048
carries no marker. Anyone deriving package placement from ADR-048's prose or diagram
gets a different lattice than the one `.go-arch-lint.yml` (per ADR-044) enforces.

### C-07 -- Cluster API server: ADR-022 mandates an HTTPS peer; ADR-054 forbids exactly that

**Severity: High. Fix type: AMENDMENT on ADR-022 (extend the existing amendment block with an ADR-054 reference).**

ADR-022's Decision: "A Kubernetes deploy that needs to reach an API server must declare
it as an HTTPS peer with the appropriate trust anchor." ADR-054 D3 decides the opposite:
the cluster API server is a control-plane dial target "declared as a field of the
method ... and not as an entry in the step's peer list, which ADR-029 reserves for
container egress." ADR-022 already carries three amendment notes (028/029/033), so the
vehicle exists; the ADR-054 hop is simply missing.

### C-08 -- ADR-026's cross-machine cache publish rests on the engine push that ADR-051 D4 removed

**Severity: High. Fix type: AMENDMENT on ADR-026 (disposition note with ADR-051 reference; if genuinely undecided, record it as an explicit open question).**

ADR-026's "Cross-machine persistence" defines a per-step `publish: <registry>` field
implemented via `POST /libpod/images/<tag>/push` -- an engine-mediated push. ADR-051 D4
removes "the engine push method on the engine interface and its control-plane caller;
the push-tag helper and the push-and-report step path". With the interface method gone,
ADR-026's mechanism cannot exist as written. Whether per-step cache publishing survives
in a control-plane-owned form (remote.Write), or is dropped in favor of deploy-only
publication, is not decided anywhere in the corpus. The remote-cache tag scheme
(`registry.Tag`) inherits the same uncertainty. This directly affects roadmap planning
for any multi-runner/cache work (and the wording of C-04's cache item).

### C-09 -- ADR-005 shows evidence of a silent in-place revision; ADR-022's historical claim dangles

**Severity: Medium. Fix type: AMENDMENT on ADR-005 (explicit revision marker; plus the missing ADR-033 network-mode note). Related index rule: see R-06.**

`ADR-INDEX.md` fixes the convention: "An ADR is content-stable: it is revised only by a
later ADR ... never by editing the original decision" (only Principles-section additions
are allowed). Two observations conflict with that:

* ADR-022 says ADR-005 "described the network opt-in as a single bit (`network: true`
  on the step)" and that "ADR-005's 'the opt-in surface is one bit' sentence is now
  historical" -- but ADR-005's current text contains no such sentence.
* ADR-005's **Decision** section itself references the *later* ADR-022 ("declared peer
  list (`peers: [...#Peer]`); see ADR-022"), which a content-stable original could not.

Either ADR-005 was rewritten in place without a marker (breaching the convention and
orphaning ADR-022's historical description), or ADR-022's description of ADR-005 is
wrong. The text supports the first reading. Independently, ADR-005's "`--network=none`
by default" is stale after ADR-033 D28 (network modes removed; every step runs under a
capsule) -- ADR-022 received that amendment note, ADR-005 did not, and ADR-029's
consequence "the step now runs with `--network=none`" has the same staleness.

### C-10 -- Inside-workdir inputs: ADR-035 says "mounted", ADR-036's probe refuted mounting

**Severity: Medium. Fix type: AMENDMENT on ADR-035 (note referencing ADR-036).**

ADR-035: "Read-only inputs mounted inside the workdir ... are part of the workdir tree and
may be captured within an output projection." ADR-036 records that a live probe "refuted
that assumption": inside-workdir inputs are **seeded** (copied via the archive endpoint
before start), not mounted; only outside-workdir inputs are image-mounted. ADR-035
carries an ADR-046 note but no ADR-036 marker, so its Decision still instructs the
refuted mechanism.

### C-11 -- ADR-012's `#EngineRecord` is triply outdated with zero markers

**Severity: Medium. Fix type: AMENDMENT on ADR-012 (one consolidated note referencing ADR-037, ADR-040 D3, ADR-042).**

ADR-012 states "Every deploy attestation includes an `engine` field" and spells the
fields snake_case (`connection_type`, `server_cert_fingerprint`, ...). Three later
decisions changed this without any note on ADR-012: ADR-042 renamed all wire fields to
camelCase (ADR-016 received precisely such a note for the same reason; ADR-012 did not);
ADR-037 reclassifies `#EngineRecord` "informational wholesale"; and ADR-040 D3 realizes
engine context as a physically separate, co-attached predicate
(`strike.dev/predicates/engine-context/v1`) rather than a field of the sealed
attestation.

### C-12 -- ADR-028's "TLS 1.3 (mandated by this ADR)" survived ADR-032's floor change unmarked

**Severity: Medium. Fix type: AMENDMENT on ADR-028 (one line in the amendment header, referencing ADR-032; can ride with the C-01 note).**

ADR-028 argues from "TLS 1.3 (mandated by this ADR's transport primitive)". ADR-032
supersedes "the earlier TLS-1.3-minimum requirement, which mandated TLS 1.3 on every
hop": external-peer hops (mediator upstream, DoT resolver) floor at TLS 1.2. ADR-008
received a supersession line for this; ADR-028 did not.

## 4. Findings -- Ambiguities

### A-01 -- Is a declared, reachable DoT resolver required for a lane with zero peers? (internal to ADR-028)

**Severity: Medium. Fix type: AMENDMENT on ADR-028 (clarifying note).**

ADR-028 states both "The resolver declaration is mandatory. A lane without a declared
resolver does not execute -- fail fast, fail hard" / "Every lane run requires a reachable
DoT resolver" **and** "lanes that need maximum throughput can declare no peers
(network=none) and stay entirely offline". ADR-033 D28 (peer-less steps get capsules
whose resolver answers NXDOMAIN for every name) does not settle whether such a lane must
still declare -- and be able to reach -- an upstream DoT resolver. The two readings imply
different operational requirements for offline lanes.

### A-02 -- The `specs/` -> `contract/` rename is recorded nowhere

**Severity: Low. Fix type: AMENDMENT (best vehicle: a short recording note on ADR-048 or ADR-047).**

ADR-017/-027/-035/-046/-047 consistently name paths under `specs/` (`specs/lane.cue`,
`specs/crossval.cue`, "One flat `specs/` directory"); ADR-044's contract-tier amendment
still names the package `specs`. ADR-049 ("Every string disjunction in `contract/`";
"five inline string disjunctions remain in `contract/`") and ADR-050
(`contract/generate.go`) use `contract/`. No ADR records the rename, so path references
in earlier ADRs silently dangle.

### A-03 -- Output identifier vocabulary: `name` (ADR-026/-027/-035) vs. `id` (ADR-046)

**Severity: Low. Fix type: AMENDMENT (one-line note in ADR-046's amendment chain or on ADR-027).**

ADR-026/-027/-035 declare outputs with `name:` (all worked YAML examples). ADR-046's
Context asserts "`#OutputSpec` nonetheless requires an `id` on every output" and its
vocabulary amendment fixes `out.ID` (`#Identifier`). The `name` -> `id` rename is
unrecorded, leaving the older examples subtly wrong against the current schema.

### A-04 -- `system_ca` / `system` trust opt-ins: deferred (ADR-021/-022) yet presupposed as existing (ADR-037/-041)

**Severity: Medium. Fix type: AMENDMENT (either resolve ADR-021's item with a reference to the deciding record, or correct ADR-037/-041 phrasing via notes; at minimum, record the gap explicitly).**

ADR-021 defers "System CA opt-in for HTTPS peers"; ADR-022 confirms it "remains a
deferred extension (ADR-021)". ADR-037 D2 then treats "the `system_ca` / `system` trust
opt-ins" as an existing residual soft spot, and ADR-041 says the system CA "is an
explicit opt-in" in the lane's peer egress. Under "newer wins" the mode presumably
exists -- but **no ADR decides it**, and ADR-021's item was never closed. The corpus
cannot answer whether the opt-in is real, and if so, on whose authority.

### A-05 -- ADR-039 staleness: snake_case fields (no ADR-042 note) and the removed target identity (no ADR-051 note)

**Severity: Medium. Fix type: AMENDMENT on ADR-039 (mirror the ADR-016-style notes: ADR-042 naming; ADR-051 D10 target removal); one-line note on ADR-037 (`lane_ref` -> `lane_digest`, ADR-041).**

ADR-039 D4 names `sealed.peers`, `sealed.observed_peers`, and
`engine_dependent.peer_attribution` -- snake_case that ADR-042 renamed; ADR-016 received
exactly this note, ADR-039 did not. ADR-039 D3's collection list still includes "the
deploy target with its pre- and post-state digests", although ADR-051 D10 removed the
target identity. Adjacent: ADR-037's provenance taxonomy names `lane_ref`, which ADR-041
renames to `lane_digest` ("populated for the first time") -- no note on ADR-037.

### A-06 -- Missing forward notes on ADR-019 and ADR-040 for the ADR-051/ADR-054 refinements

**Severity: Medium. Fix type: AMENDMENT (extend ADR-019's status note with ADR-051; add a brief amendment note on ADR-040 for ADR-051 D3/D4 and ADR-054).**

ADR-019's supersession note covers ADR-040 but not ADR-051 D3, which moved SBOM
generation from pack to deploy ("refining ADR-040 D1 from pack-implemented to
deploy-generated"). ADR-040 itself carries no marker for ADR-051 (D1 timing refined; D4
realized for locally produced images) nor for ADR-054 -- the house convention places the
note on the older document, and both refining ADRs say explicitly that they refine
ADR-040/ADR-051.

### A-07 -- ADR-009: `lane.yaml` (stage 2) vs. `bootstrap/lace.yaml` (stage 3)

**Severity: Low. Fix type: REFERENCE/erratum after operator confirmation.**

Stage 2 is "produced by `lane.yaml` running inside stage_1"; stage 3 by
"`bootstrap/lace.yaml` running inside stage_2". Whether `lace.yaml` is a typo for
`lane.yaml` or a deliberately distinct file is undecidable from ADR text (code is out of
scope for this review). Needs a one-word confirmation from the operator, then either a
fix or a clarifying half-sentence.

### A-08 -- ADR-034's "first decision to apply restricted-by-default" vs. ADR-032 carrying the same principle earlier

**Severity: Low. Fix type: optional AMENDMENT footnote.**

ADR-034's Status claims it is the "First decision to apply the 'restricted by default,
relaxed only with reason' principle"; ADR-032 (earlier in the index's
historical-logical order) also lists that principle. Since the index permits retroactive
principle mapping, ADR-032's tag may be a back-fill -- but the corpus does not say, so the
"first" claim is unverifiable as written.

## 5. Findings -- Reference and status hygiene

### R-01 -- Eight broken link filenames in ADR-028, ADR-033, ADR-037

**Severity: Medium. Fix type: REFERENCE (in-place link repair recommended; decision text untouched).**

| ADR | Broken target | Actual file |
|---|---|---|
| 028 (Status, Component 3) | `ADR-005-per-step-security-profile.md` | `ADR-005-hardened-container-profile-non-configurable.md` |
| 028 (Status, SSH mediation) | `ADR-024-ssh-known-hosts.md` | `ADR-024-ssh-peer-server-trust-enforcement.md` |
| 028 (Status, SSH mediation) | `ADR-025-ssh-agent-proxy.md` | `ADR-025-ssh-peer-client-identity-enforcement.md` |
| 028 ("One TLS verification...") | `ADR-014-audit-pipeline.md` | `ADR-014-audit-transport.md` |
| 033 (Status) | `ADR-024-ssh-known-hosts.md` | `ADR-024-ssh-peer-server-trust-enforcement.md` |
| 033 (Status) | `ADR-025-ssh-agent-proxy.md` | `ADR-025-ssh-peer-client-identity-enforcement.md` |
| 037 (Status) | `ADR-005-per-step-security-profile.md` | `ADR-005-hardened-container-profile-non-configurable.md` |
| 037 (Status) | `ADR-006-typed-secrets.md` | `ADR-006-secrets-as-typed-primitive.md` |

ADR-038, by contrast, links 024/025 correctly -- the wrong names look like an earlier
working title set that was never reconciled. A pure link-target repair does not alter
decision content; if strict append-only is preferred nonetheless, a one-line erratum per
file achieves the same.

### R-02 -- ADR-031 cites "ADR-023 (the pasta and `--splice-only` spike)" -- ADR-023 is the pointer-arguments ADR

**Severity: Low (but confusing). Fix type: REFERENCE (erratum naming the correct referent -- likely a roadmap spike, to be supplied by the operator).**

ADR-031 twice attributes the pasta/`--splice-only` spike to ADR-023 ("Companion to
ADR-023 ..."; "The egress model (ADR-023, ADR-028) realizes default-deny rootless
egress ..."). ADR-023 is "Pointer Arguments Require Justification"; no pasta-spike ADR
exists in the corpus. The referent cannot be reconstructed from ADR text.

### R-03 -- ADR-039 D5 cites an "IP-literal resolver check (ADR-024)" that ADR-024 does not contain

**Severity: Low. Fix type: REFERENCE (erratum; correct referent to be supplied -- plausibly the ADR-028/030 resolver work, but that is a guess the corpus cannot confirm).**

### R-04 -- ADR-041 cites an ADR-040 "note" that is absent from ADR-040 at this commit

**Severity: Low. Fix type: REFERENCE (erratum on ADR-041, or a note on ADR-040 supplying the missing context).**

ADR-041: "This refines ADR-040's stance that the sigstore trust root is purely a
verification-time parameter" and "Refines, without superseding, ADR-040's note that the
sigstore trust root is declared nowhere in the lane." ADR-040's text at this commit
contains neither statement. Either the note was removed (which the append-only
convention forbids) or it never existed; either way the reference dangles.

### R-05 -- ADR-033's "D24 and D26 of the ADR-028 roadmap" are undefined within the corpus

**Severity: Low. Fix type: REFERENCE (short clarifying note naming the external roadmap store as the referent, or restating the superseded content in one line).**

ADR-028 defines Components and Phases, not D-numbers; ADR-033's Status nevertheless
"supersedes in part D24 and D26 of the ADR-028 roadmap". Within the agreed information
basis (ADRs only), the supersession target is unresolvable.

### R-06 -- `ADR-INDEX.md` status conventions cannot express what the corpus does

**Severity: Medium. Fix type: AMENDMENT to the index's Format section + status-column updates (enables the OBSOLESCENCE fixes above).**

Three gaps: (a) the Format section allows only "Proposed, Accepted, Deprecated, or
Superseded by ADR-NNN", while the corpus extensively uses "Superseded in part by" and
"Amended by" -- vocabulary the index does not sanction or display; (b) the status column
marks only ADR-047, leaving ~17 amended/partially superseded ADRs indistinguishable from
untouched ones -- most damagingly ADR-024/-025, whose entire mechanisms ADR-038 replaced;
(c) the header's promise ("the older ADR's status changes to `Superseded by ADR-NNN`")
is not honored for ADR-038's supersessions. Fixing R-06 first (or together with C-01)
gives the status changes of C-01/C-02/C-03 a sanctioned vocabulary.

### R-07 -- Editorial nits (optional batch)

**Severity: Low. Fix type: REFERENCE/editorial.**

ADR-026: "uniform storage, uniform tooling, uniform tooling" (duplication). ADR-017: the
heading "Four boundaries are covered" precedes five boundary names in four bullets
(already overridden in substance by the ADR-043 note, which lists five).

## 6. Overview

| ID | Affected ADRs | Severity | Fix type | Vehicle |
|---|---|---|---|---|
| C-01 | 024, 025, 028, 033 (+029), INDEX | High | Obsolescence w/ ref + Amendments | Status lines + header notes + index rows |
| C-02 | 030 (<- 051 D4/D10, 052, 016-amdt) | High | Amendment (partial obsolescence, push row) | Dated amendment on 030 |
| C-03 | 013 (<- 040 D3 x 043; Rekor v2) | High | Amendment (reconciling addendum) | Addendum in 013 |
| C-04 | 021 (<- 040/043; 026) | High | Amendment (per-item resolution) | Notes in 021 |
| C-05 | 004 (<- 042/047/048) | Medium | Amendment | Header note on 004 |
| C-06 | 048 (<- 044 amendments) | High | Amendment | Note on 048 section 5/diagram |
| C-07 | 022 (<- 054 D3/029) | High | Amendment | Extend 022's amendment block |
| C-08 | 026 (<- 051 D4) | High | Amendment (or recorded open question) | Note on 026 |
| C-09 | 005 (x 022, INDEX rule), 029 | Medium | Amendment (revision marker) | Marker on 005; line on 029 |
| C-10 | 035 (<- 036) | Medium | Amendment | Header note on 035 |
| C-11 | 012 (<- 037/040 D3/042) | Medium | Amendment (consolidated) | Header note on 012 |
| C-12 | 028 (<- 032) | Medium | Amendment | One line in 028's header |
| A-01 | 028 (internal; 033) | Medium | Amendment (clarification) | Note on 028 |
| A-02 | 017/027/035/046/047 vs 049/050 | Low | Amendment (record rename) | Note on 048 (or 047) |
| A-03 | 026/027/035 vs 046 | Low | Amendment | Line in 046's chain |
| A-04 | 021/022 vs 037/041 | Medium | Amendment | Resolution or gap record |
| A-05 | 039 (<- 042, 051 D10); 037 (<- 041) | Medium | Amendment | Notes on 039 and 037 |
| A-06 | 019, 040 (<- 051, 054) | Medium | Amendment | Extend notes |
| A-07 | 009 (lane/lace) | Low | Reference (after confirmation) | Erratum |
| A-08 | 034 vs 032 | Low | Amendment (optional) | Footnote |
| R-01 | 028, 033, 037 | Medium | Reference | In-place link repair |
| R-02 | 031 (-> "ADR-023 spike") | Low | Reference | Erratum |
| R-03 | 039 (-> ADR-024 IP-literal) | Low | Reference | Erratum |
| R-04 | 041 (-> phantom 040 note) | Low | Reference | Erratum |
| R-05 | 033 (-> D24/D26) | Low | Reference | Clarifying line |
| R-06 | INDEX | Medium | Amendment (conventions) | Format section + status column |
| R-07 | 026, 017 | Low | Editorial | Optional batch |

## 7. Verified-consistent areas (coverage note)

To calibrate the findings: the following supersession/amendment chains were checked and
found **correct** -- ADR-008 <- 032/043; ADR-013 header <- 043; ADR-016 <- 042/051;
ADR-017 <- 043; ADR-019 <- 040 (status note); ADR-022 <- 028/029/033 (header notes);
ADR-023 <- 043; ADR-026 <- 045/046; ADR-035/036 <- 046; ADR-051 <- 054; ADR-047 -> 048
(full supersession, mirrored in the index); the dated append-only amendments of ADR-030,
ADR-044 (four amendments), ADR-046 (four, including one that supersedes an earlier
amendment of its own), and ADR-049. The index's "By principle" aggregation was
spot-checked against the ADRs' Principles sections (005, 016, 032, 037, 039, 047, 050,
053) and matched.

## 8. House amendment style (to be used by every correction)

The corpus already has four established, mutually consistent vehicles; the corrections
delivered in the following turns will use exactly these, so nothing new is invented:

1. **Header blockquote note** on the older ADR:
   `> **Amended by [ADR-NNN](ADR-NNN-....md):** <one paragraph: what changed, what stands>`
   (as used by ADR-013/-016/-017/-022/-023/-026/-035/-036/-051).
2. **Status-line partial supersession**: `Accepted. Superseded in part by ADR-NNN (...)`
   (ADR-019 style) or a leading line above Status (ADR-008 style).
3. **Dated append-only amendment section**: `## Amendment YYYY-MM-DD -- <title>`
   (ADR-030/-044/-049 style; undated variant in ADR-046/-051).
4. **Full supersession**: Status -> `Superseded by ADR-NNN` plus the matching index row
   (ADR-047 style).

Pure link-target repairs (R-01) are treated as editorial errata: the decision text is
byte-identical, only the link target changes; where strict append-only is preferred, a
one-line erratum note is the fallback.

## 9. Proposed correction sequence (one per turn)

Ordered by planning impact; each turn delivers the complete, paste-ready text blocks for
one finding (all affected files for that finding, in house style):

1. **C-01** -- the ADR-038 supersession sweep (024, 025, 028, 033, 029 line, index rows).
2. **R-06** -- index status vocabulary (ratifies the forms C-01 uses).
3. **C-02** -- ADR-030 push-row amendment.
4. **C-03** -- ADR-013 reconciliation + Rekor-v2 disposition.
5. **C-06** -- ADR-048 lattice deferral note.
6. **C-07** -- ADR-022 <- ADR-054.
7. **C-04** -- ADR-021 item resolutions (wording depends on C-08 and A-04 decisions).
8. **C-08** -- ADR-026 cache-publish disposition.
9. **C-05** -- ADR-004 exception note.
10. **C-10** -- ADR-035 <- ADR-036.
11. **C-11** -- ADR-012 consolidated note.
12. **C-12** -- ADR-028 <- ADR-032 line.
13. **C-09** -- ADR-005 revision marker (+ ADR-029 line).
14. **A-01, A-04, A-05, A-06** -- clarifications and note extensions.
15. **R-01** -- link repairs; then **A-02, A-03, R-02...R-05, A-07, A-08, R-07**.

Two findings need an operator input before their correction can be final: **A-07**
(lane vs. lace) and **R-02/R-03** (correct referents live outside the ADR corpus).

-- End of report --

## Closing report -- 2026-09-01

The correction series announced in section 9 is complete. Twenty-five
commits were delivered as git-am mboxes (author: Ingo Struck (git
commits) <git@ingostruck.de>), one finding per commit, in this
executed order: C-01, R-06, C-02, C-03, C-06, C-07, C-04, A-04, C-05,
C-08, C-10, C-11, C-12, C-09, A-01, A-05, A-06, A-02, A-03, R-01,
R-02, R-03, R-04, R-05, R-07a. Review base:
`85523afecd6b04e239affbf44a00df65b146b73b`; series end:
`be8fbfd624991eaddf810dc1fdfdb0cc824346db` plus the R-07a commit
(docs/ADR-* tree `c2e623e57df55a3ab5c2372e9aedfde352c985c3`); this
appendix lands on `1737778a8c19e03cc4f7fc9847dafd6abe0ceaeb`.

### Disposition of all findings

| ID | Disposition |
|---|---|
| C-01 | Resolved. ADR-038 supersession propagated: 024/025 status becomes Superseded by ADR-038; partial notes on 028/033; 029 note; index rows. |
| C-02 | Resolved. ADR-030's push half superseded in part by ADR-051 (D4/D10); the pull row and "recording follows the trust chain" stand. |
| C-03 | Resolved. ADR-013 dated amendment composes the ADR-040/ADR-043 notes; the Rekor-v2 failure-semantics gap is recorded, not decided. |
| C-04 | Resolved. ADR-021 per-item notes: keyless resolved (ADR-040/043); system-CA deferral verified against the tree; the cache note was later replaced (see C-08). |
| C-05 | Resolved. ADR-004's generated-not-hand-written clause scoped to its default role; qualifier ADR-042; the 042/047/048 chain told in the note. |
| C-06 | Resolved. ADR-048's lattice prose and diagram deferred to ADR-044's amendments and the lint enforcement they specify. |
| C-07 | Resolved. ADR-022's API-server-as-HTTPS-peer clause superseded by ADR-054 D1/D3; capture containers keep their peers. |
| C-08 | Resolved. ADR-026's cross-machine half superseded (ADR-051 D1/D4); the removing change's rejected alternative adopted into the corpus; the principle clause marked unbuilt; the ADR-021 cache note replaced. Severity revised High to Medium: decided but unrecorded. |
| C-09 | Resolved. ADR-005's in-place revision recorded (commit 523c5d6, offender confirmed via gitk); the pre-revision sentence restored verbatim; ADR-033 network-mode notes on 005 and 029. |
| C-10 | Resolved. ADR-035: inside-workdir inputs are seeded, not mounted (ADR-036); the capturability conclusion survives. |
| C-11 | Resolved. ADR-012 consolidated note: placement (ADR-040 D3), classification (ADR-037), naming (ADR-042, plus the caTrustType respelling recorded as fact). |
| C-12 | Resolved. ADR-028's every-hop TLS-1.3 parenthetical superseded by ADR-032; the container-facing mediator leg stays a controlled 1.3 hop, so the ECH argument stands. |
| A-01 | Resolved as a verified clarification. The offline-lane clause was the faulty side; resolver declaration and run-start probe are peer-independent, and only `strike validate`/`strike dag` never dial. |
| A-02 | Resolved. The specs-to-contract rename recorded on ADR-044 (its own internal/wire amendment as precedent). |
| A-03 | Resolved. The output key name-to-id rename recorded on ADR-027, the sole carrier; the input-side keys are ADR-027's own removal decision, not drift. |
| A-04 | Resolved. ADR-037 D2 split onto its real axes (the peer-axis mode does not exist; engine-transport `system` is the unpinned default, its ratification recorded as a gap); ADR-041's contrast clause corrected to the stronger reason. The ADR-021 half landed with C-04. |
| A-05 | Resolved. ADR-039 mirrors the ADR-016 note pair (ADR-042 renames; ADR-051 D10 target-identity removal, digests stay); ADR-037 lane_ref to lane_digest. |
| A-06 | Resolved. ADR-019 and ADR-040 carry the ADR-051 refinement notes (SBOM pack to deploy; push realized); ADR-054's absence on 040 stated as the scoping decision it is. |
| A-07 | Closed without a patch: operator confirmed `lace.yaml` is correct (the bootstrap "shoelace" referencing `lane.yaml`). |
| A-08 | Deliberately left (operator decision). A provenance footnote without planning impact; gap-sweep candidate; the settling probe is named in the R-07a commit message. |
| R-01 | Resolved. Eleven dead link targets repaired in place across 028/033/037; prose byte-identical, asserted per occurrence. |
| R-02 | Resolved. ADR-031's pasta-spike attribution was wrong at birth (history probe: ADR-023 already held pointer-arguments); the corrected reading mentions the bounded spike and references nothing. |
| R-03 | Resolved. The IP-literal split reattributed from ADR-024 to the fact of the tree and ADR-027's CUE-first principle; a second occurrence (the Principles bullet) found and covered. |
| R-04 | Resolved. ADR-041's two phantom ADR-040 citations repointed at its own Context statement; nothing written into ADR-040. |
| R-05 | Resolved. Reference note on ADR-033 locating `docs/ROADMAP-ADR-028.md` (closed and removed in 287f30d); the reference is sound, its target lives in the history. |
| R-06 | Resolved. Index status vocabulary ratified (superseded-in-part and amended qualifiers; dated in-file amendments carry no status weight); fourteen-row sweep. |
| R-07 | Partially resolved: (a) the ADR-026 duplication fixed in place; (b) deliberately left, the ADR-043 note on ADR-017 already governing the boundary list. |

### Corrections to this report, discovered during execution

- R-01: the true occurrence count is eleven, not eight.
- A-02: ADR-035 carries no `specs/` path; the affected list is
  ADR-017, ADR-027, ADR-046, ADR-047.
- A-03: the drift lives in ADR-027 alone (ADR-026/ADR-035 carry no
  `name:` output keys), and the input-side keys are ADR-027's own
  Decision.
- C-08: severity High to Medium -- the disposition existed in the
  removing commit's message (1da3a0b) and only lacked a corpus
  record.
- R-02: settled as wrong-at-birth, not a renumbering casualty.
- R-03: the faulty attribution occurs twice (D5 and the CUE-first
  principle).
- A-01 and A-04 resolved as tree-verified clarifications rather
  than recorded gaps, with the one genuinely undecided residue (the
  engine-TLS system default) recorded as a gap on ADR-037.
- The C-02 draft (section 3) planned a dated amendment for a
  partial supersession; the convention ratified in R-06 corrected
  the form: revisions by another ADR are blockquotes with status
  weight, dated sections are self-notes without it.

### Conventions ratified or exercised by the series

Blockquote notes ("Superseded in part by ADR-NNN", "Amended by
ADR-NNN") carry status weight and are mirrored in the index
qualifier; dated in-file "## Amendment" sections are self-notes and
carry none. Self-corrections of an ADR's own text use the in-file
"Supersedes, in ... above" reading device, never an edit. In-place
edits are permitted only where no meaning-bearing prose changes
(link targets; a duplicated word pair), openly enumerated in the
commit. A commit hash enters an ADR note only when the editing
event itself is the subject (C-09); otherwise the reasoning is
adopted and the hash stays in the commit message (C-08). Gap notes
end "records the gap; it does not decide it" and never reference
records that do not exist.

### Verification record

Every anchor's docs/ADR-* tree hashed identical to the predicted
post-patch tree -- twenty-five of twenty-five, zero drift -- which
also proves every mbox landed unmodified. Every edit ran behind
exact-anchor assertions that fail before any write; they fired
twice (the A-04 file tails) and prevented a bad patch both times.
Every mbox was round-trip verified by `git am` onto a pristine base
with tree-hash comparison; the two patches built without a fresh
anchor (C-03, C-08) were verified on both candidate bases.

### Left in the corpus for the announced gap-collection sweep

Rekor-v2 submission-failure semantics (ADR-013); the un-ratified
engine-TLS system default (ADR-037); the caTrustType respelling
(ADR-012); the unbuilt cross-machine clause's verbatim copy in
DESIGN-PRINCIPLES.md (ADR-026's Scope places it there, outside this
sweep's file scope); cross-machine cache direction (ADR-021); the
input-side field-name question (noted in the A-03 delivery); R-07
item (b); A-08.

-- End of closing report --
