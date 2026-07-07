# Dual Type-Safety Audit -- Retrospective

| | |
|---|---|
| Date | 2026-07-07 |
| Audited tree | `ebf8960e3d7e421a07588d3238ef5957c9d32c47` |
| Inputs | Two independently produced audits of the same tree from a near-identical prompt: the analysis-instance report ("A", `strike-type-safety-audit-ebf8960.md`) and the executor-harness report ("E", `TYPE-SAFETY-AUDIT.md`), plus the executor's fact extractor (`audittypeflow`, retained as blueprint) |
| Subject | What running the same audit through two harnesses taught about the audits, the codebase, and the workflow itself |
| Outcome | Mechanism taxonomy adopted; procedure changes ratified (section 6); fix program written into the roadmap store (items 0071-0084); disputed set queued for adjudication (item-0072) |

The two source reports are working papers retained by the operator; folding
them (and earlier retrospectives) into this directory is a separately
ratified migration step and out of scope here.

## 1. Context and experimental setup

The operator ran the same type-safety survey twice, deliberately varying the
harness while holding the synthesis model class constant, to allow a
like-for-like comparison of the two lanes of the documented workflow:

- **A** -- the analysis instance: read-only grounding against the pinned
  tree, no build/codegen toolchain, single context, one self-built
  parse-only AST scan (stdlib `go/parser`), manual whole-module reading,
  root-cause-clustered prose findings.
- **E** -- the executor harness: full toolchain, a purpose-built
  type-checked extractor (`go/packages` + `go/types`, 921 facts), an
  18-agent trace sweep, an adversarial refute-first verification stage, and
  mechanical synthesis. Approximately 4.7M agent tokens, ~2000 tool calls,
  three runs (two aborted on session quota, recovered by journal-backed
  resume).

Both sides independently invented the same class of tool -- an AST fact
extractor -- differing only in whether the type checker was available. That
convergence is itself a finding: the tool wants to exist, so it is being
reified as a standing gate (item-0073) instead of being rebuilt ad hoc by
whichever lane runs the next audit.

## 2. Method comparison

| Dimension | A (analysis instance) | E (executor harness) |
|---|---|---|
| Grounding | pinned clone, read-only | pinned working tree, full toolchain |
| Generated code | derived from CUE + `@go` annotations (gen files gitignored) | actual `*.gen.go` after codegen; 5 gen-scoped findings |
| Type inventory | prose + CUE + hand-written types | gen files only (agent stage); the extractor itself saw all strike named types, so the narrowing happened in agent configuration, not tooling |
| Fact base | parse-only scan, 8 shape classes | type-checked extractor, 9 fact kinds, 921 facts |
| Judgment | single-pass, whole-context | 18 parallel tracers + refute-first single-vote verifier |
| Verification | manual re-read of every cited region | adversarial re-open of every finding; 40 rejections preserved with reasons |
| Granularity | ~55 root-cause clusters + 9 cross-cutting patterns | 136 site-level findings (dedup on file:line:category) |
| Meta layers | linter-blind-spot mapping | repo-history correlation, workflow-model critique, gate-evolution proposal |
| Cost | one session, one scan | ~4.7M tokens, ~2000 tool calls, 3 runs |

Raw counts are not comparable across the two reports: A counts root causes,
E counts sites. Section 7 reconciles them at cluster granularity.

## 3. Quantitative reconciliation

E's pipeline: 921 facts -> 226 raw findings -> 176 deduped -> 136 verified
(122 confirmed, 14 corrected, 40 rejected). A's report: 56 itemized
findings across four categories, 9 cross-cutting patterns, plus cleared
classes documented for auditability.

At cluster granularity (section 7): 27 clusters found by both, 9 clusters
E-only, 9 clusters A-only, 5 clusters disputed between A's filing and E's
verifier. The overlap core covers every high-fan-out defect family; the
single-side and disputed sets are where the information is -- three of them
change remediation plans (sections 4.1, 4.2), which is the concrete return
on running the audit twice.

## 4. Corrections established by the comparison

All claims below were re-verified against the pinned tree during this
retrospective, not taken from either report on trust.

### 4.1 E-side facts that correct the A report

1. **The capsule step-identity domain is not `#Identifier`.**
   `internal/deploy/deploy.go:608` passes
   `captureKey(d.StepID, sc.ID)` -- a `capture:<step>:<capture>` composite
   containing colons -- as the `name`/`stepID` into `startUnitCapsule ->
   capsule.New -> resolver.New / mediator.New / newSSHForwarder`, while
   deploy.go:707 and :747 pass plain step ids on the same path. A's C1-1
   presented the chain as a uniform Identifier degradation; a retype derived
   from that framing would have minted grammar-violating Identifier values
   by cast (exactly A's own X-3 hazard class). E's verifier caught this in
   its *rejections* (164-166) -- while E's *kept* finding 113 describes the
   same chain without the caveat. The correction only becomes visible by
   reading both reports plus the rejected appendix. Consequence: the retype
   is gated on a ratified unit-key design (item-0080).
2. **A cleared `RunOpts.Tmpfs` incorrectly.** A's C3-11 filed the Tmpfs map
   under free-form env-name keys; the key is a container-internal absolute
   mount path (`"/tmp"` literal, consumed as `specMount.Destination`).
   E finding 64 is right. Misclassification, not a recall miss.
3. **A recall misses, verified real:** `#PackSpec.configFiles`
   `[Path=string]` key (lane.cue:241-243; E 144/21/48);
   `internal/lane/symlink.go` `linkRel` as untyped RelPath-grammar across
   three packages (E 126); the whole of `contract/provenance`
   (`fetchedAt: string` x4 vs `primitive.#Timestamp`, E 86) and
   `contract/target` (`url?: string`, E 30) -- A's "entire CUE tree" claim
   had holes in the concept tier; `DigestFromHex(body string)` forcing a
   detype when composed with its documented inverse `Hex()` (E 82/83 --
   A had filed the constructor as sanctioned, E's composition argument is
   sharper); the `artifactTypeImage/File` untyped consts in cmd (E 133);
   the ad hoc anonymous decode structs in verify duplicating typed gen
   shapes (E 94/95); `BaseSBOMReferrer.Digest` field (E 41); itemized
   test-tier findings A had only aggregated.

### 4.2 A-side findings that survive E's verifier

Verified present at the anchor and absent from E's findings and rejections:

1. **The OIDC id token is a bare `string`** through
   `subjectFromIDToken` / `produceKeylessBundles`
   (internal/deploy/keyless_producer.go) while `lane.SecretString` exists
   as the typed redacting carrier -- the single most security-relevant
   finding, and structurally invisible to E because the agent-stage type
   inventory was gen-files-only (SecretString is hand-written). The
   extractor's `strikeNamed` would have seen it; the narrowing was
   configuration. Rule change in 6.3.
2. **Duplication set:** `canonicalize` byte-identical in mediator and
   resolver; `type Decision string` defined twice with identical constants;
   `sshTarget` twins; `isTimeoutErr` twins. E's per-package and per-type
   decompositions both slice across duplication; A's whole-module grep is
   what caught it.
3. **In-band sentinel pattern (X-3):** grammar-violating zero values carried
   inside regex-constrained named types (`Digest("")`,
   `OutputRef{Output: ""}` as the documented empty-output key, empty
   `ImageRef` trust-root casts). Interacts directly with 4.1.1: both are
   sightings of "the value domain exceeds the nominal grammar".
4. **Validation displacement (X-8/C2-11):** population sites cast
   (`primitive.Digest(raw.Digest)` at the engine-inspect ingest) while
   downstream consumers re-parse defensively; `ParseDigest`'s own doc names
   the ingest boundary the casts bypass.
5. **Structural mirror:** `container.ConnectionInfo` duplicates the
   `endpoint.#Engine*` union untyped and is bridged by a stringly
   discriminator plus a 20-line field copy (`engineRecords`). E filed only
   the fingerprint fields (53).
6. Smaller survivors: the Go-side re-derivation of the CUE default for
   `#DeployKubernetes.strategy`; the anonymous 60-char inline regex on
   `#Lane.registry`; seedtar's Sprintf-composed blob-path map keys; the
   trustlayers vocabulary existing only as CUE-export enums while the
   verify command keys maps by bare layer-name strings; the WrapTag
   compose / `parseImageRef` decompose round trip with its unreachable
   "latest" fallback; SpecHash's stale parameter doc and its
   always-empty-in-production `sourceHashes` parameter.

### 4.3 E-internal inconsistencies

- Finding 145 (OIDC issuer, kept, citing `endpoint.#URL` as the available
  type) vs rejection 155 (OIDC issuer/identity in the predicate, rejected
  as "no strike scalar applies") -- same question, opposite verdicts,
  because parallel verifiers improvised the rule instead of citing one.
- Kept 113 vs rejections 164-166 (section 4.1.1) -- the kept finding and
  the rejections carry contradictory remediation implications.
- Rejections 146/147 dismissed target.cue findings as "speculative" while
  the roadmap store already carries the pending decision (item-0057) they
  feed; the verification stage had no store context.

### 4.4 Attribution honesty

The experiment does not isolate model capability: the two runs differed in
harness, tooling, state access, and verification structure, not only in
model. Where a difference is explained by method (inventory configuration,
adversarial verification, whole-context reading), this document attributes
it to the method. No "model X found this because it is model X" claims are
made or should be quoted from here.

## 5. Mechanism taxonomy for defect analysis (adopted)

E's repository-history correlation showed the findings are not uniform
debt; each migration wave's execution mechanism left a characteristic
residue. The taxonomy is adopted for all future defect analysis: every
defect gets a mechanism label, and the primary retrospective output is the
mechanism fix (a gate, a channel, an owner), with the code fix secondary.

- **M1 gate-narrower-than-goal.** The item's goal states a tree-wide
  invariant; the standing gate observes one syntactic position. Canonical:
  item-0034 vs `linttypeconv` (call-argument position only).
- **M2 anti-initiative without a follow-up channel.** Byte-exact scope
  discipline worked as designed and left half-migrated seams; the mandated
  "report as follow-up candidate" never became items. Canonical: RunOpts
  gained a typed Image while its sibling path fields stayed string.
- **M3 deferral without an owner.** Allowlist entries, lossy `@go`
  redirects, and "accepted until revisited (YAGNI)" notes with no item id
  attached. Canonical: the `mediator.canonicalize` allowlist entry; the
  lane.cue secrets-map note.
- **M4 fresh code regresses where no gate observes.** HEAD-adjacent
  contract fields whose doc comments state a typed grammar verbatim while
  declaring bare string.
- **M5 toolchain loss mislabeled as debt.** gengotypes cannot preserve a
  constrained map key without an `@go` redirect; the redirect chose
  `map[string]` where the attest package proves `map[primitive.Identifier]`
  is expressible. The defect class needs an annotation-level fix and a
  visibility rule, not caller-side churn.
- **M6 never-scoped subsystem.** Packages outside every migration arc's
  file list simply kept their pre-scalar shape (mediator, capsule, the
  output handle surface).

## 6. Ratified procedure changes (operator, 2026-07-07)

### 6.1 Authoring clauses (content ratified; placement pending the workflow-doc restructuring decision, item-0071)

1. **Acceptance observes the invariant.** When an instruction's goal states
   a tree-wide invariant, its acceptance is a tree-wide observation -- an
   analyzer run or an exhaustive structured search over every named surface
   -- never a site list. A site list certifies the list; only the
   observation certifies the invariant.
2. **Sibling closure.** An instruction that types or otherwise migrates one
   field of a struct, one method of an interface, or one arm of a union
   enumerates every sibling of the same value class -- each either in scope
   or named as a deferral with its follow-up item id.
3. **Domain verification before retype.** Before an instruction narrows a
   value's type, the author verifies the full value domain at every write
   site, module-wide including test/: in-band sentinels and composite or
   namespaced values outside the target grammar block the retype until they
   are removed or the target design is widened by ratified decision.
4. **Deferrals carry owners.** Every deferral a gate can see -- a linter
   allowlist entry, a lossy `@go` redirect, an accepted-until-revisited
   note -- carries the roadmap item id that owns it. A deferral without an
   owner is a defect of the change introducing it.

### 6.2 Executor completion report (content ratified; placement in AGENTS.md pending item-0071)

The completion report ends with two mandatory sections: **Observations** --
the verbatim output of every acceptance observation the instruction names --
and **Follow-up candidates** -- every correct-but-out-of-scope improvement
encountered, or the single word "none". A missing section is a gate
failure. This closes the lossy half of M2.

### 6.3 Audit and verification procedure

- **Findings data contract.** Every future audit -- either lane -- emits
  machine-readable findings (JSONL: id, file, line, category, types, scope,
  claim, evidence, chain, plus blob-SHA provenance). Prose reports render
  from the data, never the reverse. `audittypeflow`'s schema is the
  starting point; the `-report` mode of the standing gate (item-0073)
  carries it forward.
- **Type-inventory union rule.** Any type-adoption survey's inventory is
  the union of generated types, hand-written strike named types, and
  CUE-only vocabularies. Never gen-files-only (cause of 4.2.1).
- **Category rulebook as input.** Survey categories and boundary/ownership
  rules are a versioned artifact handed to every agent, not improvised
  per-agent. First codification task (item-0072): split "not typed" into
  D1 (existing type not applied) and D2 (type missing for a recurring
  grammar) -- the definitional gap behind several E rejections.
- **Verifier verdicts cite rules.** Every keep/reject verdict names the
  rulebook clause it applies; the verification stage receives the roadmap
  store as context (cause of 4.3).
- **Dual-run policy.** Full dual audits are reserved for tree-wide
  invariants and high-stakes analyses; the default mode is the
  deterministic extractor plus one judgment pass; the multi-agent sweep
  runs per release or per migration wave. The diff between independent
  runs is treated as the product and is retro-analyzed as such.
- **Ad hoc executor tooling.** Throwaway analysis tools live in spike
  worktrees and are never committed; promotion to `tools/` happens only
  through the normal instruction path with gates. (The audit tool tarball
  contained a compiled binary; only source enters the repo, as blueprint
  input to item-0073.)

## 7. Cluster reconciliation register

Granularity: one row per root-cause cluster. "A" cites the analysis
report's finding ids, "E" the executor report's numeric ids (r = rejected
by E's verifier, but listed because the rejection carries information).
Status: both / A-only / E-only / disputed. Disposition names the roadmap
item (or existing item / pending fork) that owns the cluster.

| ID | Cluster | A | E | Status | Disposition |
|---|---|---|---|---|---|
| R-01 | capsule/mediator/resolver step-identity chain | C1-1 | 113,68,24,170,65; r164-166 | both | item-0080 (unit-key decision) |
| R-02 | engine option structs: path fields + Tmpfs key | C1-2 | 59,63,58,60,61,50,64 | both | item-0050 (absorb; see sec. 10) |
| R-03 | output.cue imageRef/layerDiffID contract root | C4-1, C1-4 | 100,148,97,25,26,161,157 | both | item-0052 (existing) |
| R-04 | registry Tag/WrapTag/WrapDigest untyped returns/params | C1-14, C2-3, C2-5 | 34,7,90,105,35 | both | item-0078 |
| R-05 | deploy-artifact name roundtrip | C2-1, C1-12, C1-13 | 110,8,0,20,109 | both | item-0076 (keys) + call sites ride |
| R-06 | secrets map keys + SecretRef.name | C3-1, C4-8 | 19,108,130,143,132,29,131 | both | item-0076 |
| R-07 | stepInputs.handles keyed by dotted ref | C3-2 | 175,111 | both | item-0078 |
| R-08 | stepPorts composite key + captureKey twins | C3-3, X-6 | 114; r1,r69,r171,r172,r11 | both | item-0080 |
| R-09 | canonical-host maps (peers/allowlist/CA cache) | C3-4, C4-14, X-4 | 78,22,77,116,79,80; r167-169 | both | item-0080 (canonical-host decision) |
| R-10 | peer-anchor dedup map + composite anchor strings | C3-5 | 23 | both | item-0075 |
| R-11 | SSH target/records host+port roundtrips, known_hosts render/parse | C2-2, C2-4, C1-17 | 117,118,119,120,66,67,55 | both | item-0080 |
| R-12 | fingerprint construction/carriers in six packages | C4-10, X-2 | 93,52,54,74,76,162,53 | both | item-0075 |
| R-13 | attest/engine contract fingerprints + ResolverRecord.host | C4-5 | 4,150,151,152,153,75,134,163 | both | item-0075 |
| R-14 | hand-written trust.go drops CUE field types | C4-4 | 72,73 | both | item-0075 |
| R-15 | verify chain: laneDigest/wantHex/subject digests | C1-7, C1-11 | 13,96,12,94,95 | both | item-0081 |
| R-16 | SBOM subjectDigest chain in executor | C1-11 | 45 | both | item-0081 |
| R-17 | captureSnap untyped id/image fields | C1-8 | 2 | both | item-0080 |
| R-18 | LaneDefaults.timeout default-idiom collapse | C4-3 | 27,128 | both | item-0076 |
| R-19 | configFiles path-keyed map | -- | 144,21,48 | E-only | item-0076 (contract) + item-0079 (consumer) |
| R-20 | OIDC issuer/identity fields | C4-6, C1-16 | 145; r155 | disputed (E-internal) | item-0076, gated identity-typing decision |
| R-21 | id token not carried as SecretString | C4-13 | -- | A-only | item-0081 |
| R-22 | #Lane.registry anonymous inline regex | C4-2 | -- | A-only | item-0076 |
| R-23 | seedtar blob-path Sprintf map keys | C3-9 | -- | A-only | item-0079 |
| R-24 | trustlayers vocabulary untyped in verify maps | C3-10 | (adjacent r154,r135-142) | disputed | enum-policy decision; then item-0081 |
| R-25 | rekorKeys hex-string map keys | C3-8 | 84 | both | item-0081 |
| R-26 | cast-at-ingest / defensive re-parse displacement | C2-11, X-8, C2-6 | -- | A-only | item-0082 |
| R-27 | DigestFromHex(string) vs Hex() composition | (C4-12, filed sanctioned) | 82,83 | E-only (sharper) | item-0082 |
| R-28 | ImageRef constructor policy + executor substring re-check | X-8 | 49,107 | both | item-0082, gated constructor decision |
| R-29 | in-band grammar sentinels | X-3 | -- | A-only | item-0083 |
| R-30 | Decision type defined twice | X-5 | -- | A-only | item-0080 |
| R-31 | canonicalize/isTimeoutErr byte-identical twins | X-4 | (79 mentions) | A-only | item-0080 |
| R-32 | ConnectionInfo mirrors endpoint engine union | C2-9 | 53 (fields only) | both (structure A-only) | fingerprints item-0075; mirror collapse recorded as open candidate |
| R-33 | strategy default re-derived in Go | C2-10 | r140 (enum angle only) | A-only | item-0076 |
| R-34 | engine address scheme-parsed threefold, untyped | C4-11 | r56 | disputed | item-0072 |
| R-35 | known_hosts [host]:port projection outside endpoint | C1-9 | r51 | disputed | item-0072 |
| R-36 | dialUpstream JoinHostPort -> DialTCP re-split | C1-10 | r121 | disputed | item-0072 |
| R-37 | AbsPath/RelPath grammar-method shapes (cause) vs prefix-concat consequence | C1-3 | 18 kept; r123,r17,r124 | disputed | item-0072; feeds item-0079 |
| R-38 | provenance fetchedAt untyped x4 | -- | 86 | E-only | item-0077, gated timestamp-doc decision |
| R-39 | target.cue url/type fields | -- | 30; r146,r147 | E-only | item-0057 (existing decision item) |
| R-40 | artifact-type consts untyped in cmd | -- | 133 | E-only | item-0082 |
| R-41 | TLSConfig host file paths untyped | -- | 173 | E-only | gated host-path-domain decision; then item-0050 scope |
| R-42 | test-tier fixtures re-spell grammars | C1-18, C2-7, C2-12, T | 85,87,88,98,5,42,31,43,91,115,99,83,32,33 | both | ride owning items; overlap noted on item-0056 |
| R-43 | SpecHash keying doc-drift + dead sourceHashes param | X-7 | r36 | A-only (r36 confirms key shape) | item-0078 |
| R-44 | @go typed-key precedent / gen-anchor volatility | C3-1 contrast | history sec. 5, limits 4 | both (method) | recorded here; informs item-0076 |
| R-45 | no-op string casts on Hex() slices | C2-7 | r89 (test twin) | A-only, trivial | rides item-0082 |

## 8. Disputed set for adjudication (item-0072)

Each dispute below is re-adjudicated with an explicit rule citation; the
outcome is recorded against the item and, where it generalizes, codified in
the category rulebook (6.3).

1. **R-34 engine address.** A files the `CONTAINER_HOST` string (scheme
   inspected in three places, no carrying type) as a typing gap; E's
   verifier rejects because no existing scalar models the `unix://` |
   `tcp://` compound and `endpoint.Address` cannot represent the socket
   form. The dispute is definitional (D1 vs D2, 6.3); the ruling decides
   whether a compound engine-address type is wanted or the triple parse is
   an accepted boundary with a single owned parser.
2. **R-35 formatHost.** E's verifier rejected on "the bracket grammar is a
   distinct wire form Authority() does not produce" -- true, but answering
   a claim A did not make. A's claim is ownership: the third `Address`
   projection is implemented outside the package that owns the other two.
   Ruling wanted: do wire projections of a concept type belong to the
   owning package as a rule.
3. **R-36 dialUpstream.** (ip, port) is joined by the caller and re-split
   as the first act of the strike-internal callee. E: canonical stdlib
   shape at a network boundary. A: churn across an internal signature that
   could take the pair. Ruling wanted: is a stdlib-shaped signature on an
   internal wrapper a boundary.
4. **R-37 path grammar methods.** E's verifier exempted the owning
   package's `Clean()/Dir()/HasPrefix(string)` shapes while keeping the
   downstream prefix-concat consequence (18). Ruling wanted: scope of the
   owning-package exemption when the methods' shapes force every caller
   back to strings; outcome shapes the containment-helper design in
   item-0079.
5. **E-internal 145 vs 155** (section 4.3): resolved by the rulebook, not
   by fact-finding; the OIDC design question itself is a separate ratified
   decision feeding item-0076.
6. **Boundary catalog codifications** surfaced by E rejections and A
   clearances that were correct and should become named rules:
   third-party digest handles (`v1.Hash.String()` is not a strike detype);
   log/error-only formatting exclusion and its limits (A's safeName/tag
   threading sits at the edge); wire-discriminator literals as
   boundary-legitimate (interacts with the enum-hoisting decision).

## 9. Data-retention decision

No unified per-finding JSONL is committed for this round. Rationale: the
cluster register above is the durable reconciliation product; per-finding
site data is pinned to `ebf8960` line numbers and decays with the tree
(E's own limits section, point 8); the executor's verified-findings JSON is
retained by the operator for the adjudication pass; and the ratified
findings contract (6.3) makes every *future* audit emit machine-readable
data natively, so retro-transcribing this one buys little. If the
publication work later wants the raw data set in-tree, that is a one-item
follow-up against the operator-retained JSON, not a transcription from
prose.

## 10. Store dispositions and adjustments to existing items

New items 0071-0084 were created `proposed` in the same change set as this
document; the phase sequencing ratified by the operator is recorded in each
item body, and `_order.md` placement is executor-lane, riding the first
instruction of the arc. Adjustments to existing items (executor-lane,
to ride that same instruction):

- **item-0050**: absorb the engine option-struct typing (RunOpts.Workdir,
  Seed.Path, Mount.Target, VolumeMount.Dest, ImageVolume fields, Tmpfs key
  -- register R-02) into the container Tier-1 CUE work so those structs are
  touched once; link this retrospective. The TLSConfig fields (R-41) join
  only after the host-path-domain decision.
- **item-0052**: link this retrospective (R-03); note that items 0078/0079
  depend on it and that both audits enumerate its downstream consumer set.
- **item-0056**: note the overlap with R-42 (crossval vector structs are
  part of the same typed-fixture intent).
- **item-0057**: add the target.cue findings (R-39; E 30, rejected 146/147)
  as inputs to the pending method/target namespace decision.

## 11. References

- A: `strike-type-safety-audit-ebf8960.md` (analysis instance, 2026-07-07).
- E: `TYPE-SAFETY-AUDIT.md` (executor harness, 2026-07-07), including its
  rejected-candidates appendix and reproduction section.
- Blueprint tool: `audittypeflow` (main.go + go.mod), operator-retained;
  evolution path is item-0073.
- Anchor for every code claim: `ebf8960e3d7e421a07588d3238ef5957c9d32c47`.
