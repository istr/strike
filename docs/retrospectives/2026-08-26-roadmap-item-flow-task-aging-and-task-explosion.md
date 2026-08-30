# Roadmap Item Flow: Task Aging and Task Explosion -- Retrospective

| | |
|---|---|
| Date | 2026-08-26 |
| Audited tree | `e18d8a4e61aa1042b981cb88905728728aa6bca3` |
| Inputs | The public git history only (698 commits, 2026-03-29 to 2026-08-26): the `roadmap/` item store and the 203 commits that touched it, the `roadmap-items` skill (`.claude/skills/roadmap-items/`), `AGENTS.md`, `AI-WORKFLOW.md`, `AI-ORCHESTRATION.md`, `docs/AI-REVIEW-AND-RETROSPECTIVES.md`, and the retired prose `docs/ROADMAP-*.md` files (2026-05-16 to 2026-06-20) as origin context. No project memory, no transcripts, no uploads, no working tree other than the checked-out commit. |
| Subject | How work items flowed through the store; where older items were made obsolete by newer work (task aging); where one completed item produced several new ones (task explosion); which patterns recur; and which workflow rules produce them systematically |
| Outcome | Descriptive findings, every claim pinned to a commit; candidates for confirmation in section 7. No planning state: this document proposes no items and changes none. |

This is a context-free read of one snapshot and its history, commissioned as
described in `docs/AI-REVIEW-AND-RETROSPECTIVES.md`. Per that document it
disclaims its own authority: the classifications below are candidates for the
operator to confirm against the live tree, not verdicts. Where a number rests on
an interpretation (chiefly the executed-versus-retired split in section 1.3),
the interpretation is stated and the raw table in the appendix lets a reader
redo it.

## 1. Scope, method, definitions

### 1.1 Scope

The unit of analysis is the roadmap item: 140 files `item-0001` to
`item-0140`, 89 under `roadmap/completed/`, 51 under `roadmap/`. The store
was created on 2026-06-20 (`6ba0c61` adds the skill, `3c173c6` migrates the
prose roadmaps into it) and is 68 days old at the audited tree. The prose era
before it -- thirteen `docs/ROADMAP-*.md` and `docs/ADR-*-ROADMAP.md` files
between `2b7b3f7` (2026-05-16) and the migration -- is read only for the
origin of store items and for whether the phenomena predate the store.

### 1.2 Method

Every commit that touched `roadmap/` was walked in order and each version of
each item file parsed (frontmatter fields, body, final summary). From that
per-item timeline the analysis takes creation, ratification, every
content-changing edit before completion, and completion. Origins were taken
from explicit statements in the item bodies ("Absorbed from the item-0114
completion report", "Split out of item-0024", "Surfaced by item-0119",
"Register row R-05") and from commit subjects and bodies ("add items 0115-0117
(item-0108 follow-ups)"). Every superseding landing named in a final summary
was checked to exist in the history. The extraction script is reproduced in
appendix B so the tables can be regenerated from a clone.

### 1.3 Definitions used

**Task aging** is taken in the broad sense commissioned for this retrospective:

- *full* -- an item retired without its own implementation because a newer
  item, a ratified decision, or a landing elsewhere made it moot;
- *partial* -- an open item whose title, goal, acceptance intent, links, or
  notes had to be amended because the tree or the plan moved under it, or an
  executed item that landed narrower than written;
- *aging at birth* -- an item created for work that had already landed.

**Task explosion** is one completed item, one ratified decision, or one
retrospective producing several new items, or amendments to several existing
items, in its wake.

**Executed versus retired.** The store's status model has three states,
`proposed -> ratified -> done` (`references/schema.md`, "Status model and the
ratification gate"), and no state for an item that was withdrawn. An item that
was superseded is therefore marked `done` exactly like one that was built. The
split used below rests on the `## Final summary` prose of each done item and
was verified against the landing commits those summaries name. Two items
(0043, 0059) whose work was done as a side effect of another item are counted
as retired, not executed, because no commit was made for them.

## 2. The item flow in numbers

### 2.1 Timeline of the store

| Date | Event | Commit |
|---|---|---|
| 2026-05-16 | First prose roadmap (`docs/ROADMAP-ADR-028.md`) | `2b7b3f7` |
| 2026-06-12 | `docs/ROADMAP-STATUS.md`: a cross-roadmap summary with its own "Execution order (cross-roadmap)" section, hand-synchronized with four other roadmap files | `daf2d34` |
| 2026-06-14 | Commit subject "make a roadmap the single source for planning state" | `43e93ff` |
| 2026-06-20 | `roadmap-items` skill added; five prose files (1587 lines) replaced by items 0001-0016 (flipped to `ratified` on transcription) plus 0017/0018 derived from the retired ADR-028 roadmap | `6ba0c61`, `3c173c6` |
| 2026-06-20 | Same day: items 0019-0025 added (spec-layering arc), 25 items exist by evening | `bb91468`, `ef1bc70` |
| 2026-07-07 | Largest single batch: 14 items 0071-0084 from the dual type-safety audit retrospective | `e1ff84d` |
| 2026-07-18 | Second largest: 11 items 0101-0112 from the ADR-051 arc decomposition, plus 0113 the same day | `18161ea`, `10d0d22` |
| 2026-08-19 to 08-26 | Amendment wave: 23 content amendments on 18 items in 19 commits over eight days; 20 `depends_on` edges recorded at once | `30944c7` .. `e18d8a4`, `dc83c97` |
| 2026-08-23 | Last batch: adr-052-lock-free arc proposed (0137-0140), the only `proposed` items at the audited tree | `6fba150` |

### 2.2 Stocks and flows

At `e18d8a4`: 140 items -- 89 `done`, 47 `ratified`, 4 `proposed`. Of the 89
done, 72 were executed, 15 were retired without their own implementation, and
2 were closed retroactively for work that predated the store (section 3.1).

| Month | Items created | Items closed (`done`) | Content amendments before completion | Open set at month end |
|---|---|---|---|---|
| 2026-06 (from 06-20) | 61 | 31 | 13 | 30 |
| 2026-07 | 52 | 32 | 26 | 50 |
| 2026-08 (to 08-26) | 27 | 26 | 36 | 51 |

The open set (items not yet `done`) doubled in the first three weeks -- 25
on the migration day, 47 on 2026-07-10 after the retrospective batch -- and
has sat at 50 to 56 since 2026-07-20. Creation has slowed each month while
closure held steady, so the store is no longer growing. What grows instead is
the age of what is in it (section 2.4) and the amendment traffic on it: the
36 pre-completion amendments of August exceed the 27 items created.

### 2.3 Two speeds

Executed items are fast. Of 72, the median time from creation to `done` is 2
days; 39 were closed within two days of being created and 54 within seven.
Eleven commits move a fresh item to the top of `_order.md`, ten of them in
the commit that ratifies it (`04f6e8d`, `8e3ceec`, `fbf4aa8`, `040cb02`,
`e556b18`, `4869c61`, `b9c5d49`, `7f4674a`, `453fe01`, `4834483`,
`f3918aa`), and 19 commit subjects announce a reorder, reschedule, or
restructuring of the order. The store therefore runs as two
queues: a fast lane of items created from the work in progress and executed
within days, and a tail that is ratified but keeps being scheduled behind the
fast lane.

The six executed items that took more than 30 days all come from the tail:
0011 (65 days) and 0012 (63) from the migration cohort, 0086/0087/0088 (44)
from the ADR-049 consequence batch, 0095 (42) from the build-toolchain batch.

Items retired without implementation are faster still: median lifespan 8
days, and six of the 17 were superseded within three days of their creation
(0043 and 0047 on the day they were written, 0033 and 0065 after one day,
0038 after two, 0100 after three). Those six were made obsolete by the next
planning step, not by tree drift -- see section 3.5.

### 2.4 The tail ages

Of the 51 open items, 36 are older than 30 days and 9 have been open since
the store's first day (0002-0008, 0013, 0016). The `acceptance_intent` field,
specified as "The intent of acceptance -- what must become true -- not
byte-exact greps or file lists. Drift-invariant." (`references/schema.md`,
field reference; `goal` is the field held to one line), has a median length
of 406 characters across all items; the
six longest belong to open items (0016 at 1960 characters, 0080 at 1307, 0050
at 1228, 0126 at 979, 0084 at 953, 0079 at 952). On 34 items the field
changed length after creation; the largest growth is item-0016 (+1608
characters over four amendments). Open items accrete scope and history while
they wait.

### 2.5 Batch creation

Thirteen commits created three or more items at once; together they account
for 83 of the 140 items.

| Commit | Date | Items | Source |
|---|---|---|---|
| `6ba0c61` | 06-20 | 14 | Transcription of the prose roadmaps (0001-0014; 0015/0016 in `1d2babc`) |
| `ef1bc70` | 06-20 | 6 | spec-layering arc plan (ADR-047) |
| `371640f` | 06-26 | 3 | ADR-048 primitive/concept model (0037-0039) |
| `d9d2565` | 06-27 | 4 | endpoint-model arc (0040-0043) |
| `768b60a` | 06-30 | 7 | CUE contract review (0051-0057) |
| `10d5e55` | 07-03 | 3 | lane-dag-decomposition arc (0066-0068) |
| `e1ff84d` | 07-07 | 14 | Dual type-safety audit retrospective (0071-0084) |
| `ce859ca` | 07-09 | 7 | ADR-049 ruling of the disputed set (0086-0092) |
| `d2be51e` | 07-11 | 4 | Beta cut / build-toolchain (0094-0097) |
| `18161ea` | 07-18 | 11 | ADR-051 arc decomposition (0101-0112) |
| `28f3483` | 08-11 | 3 | item-0108 follow-ups (0115-0117) |
| `548eaaf` | 08-20 | 3 | Harness arc (0132-0134) |
| `6fba150` | 08-23 | 4 | adr-052-lock-free arc (0137-0140) |

The three largest batches are not follow-ups of a single item: two come from
audits or rulings (`e1ff84d`, `ce859ca`) and one from decomposing an accepted
ADR into executable slices (`18161ea`). Single-item follow-up creation is the
common case but the small one; the batches set the open-set level.

### 2.6 The prose era as origin context

The prose roadmaps already carried both phenomena.

Follow-ups were tracked as "Deferred follow-on" paragraphs inside the arc
they came from. `docs/ROADMAP-sigstore-test-harness.md` at `3c173c6^` holds
two such paragraphs under the CT arc ("whether strike's own verify should
enforce the embedded SCT ... is its own item, sequenced after this arc";
"Pulling the ctlogs entry into liveTrustRoot is the remaining step ...
deferred until after the golden / conformance arc"); they became items 0011
and 0012 on migration. Commit subjects of the era show the same channel
operating across files: "fold in two follow-on items" (`0fb214f`), "refresh
status across four roadmaps after the B-5 follow-ons land" (`083b50a`).

Aging shows as status lag between files. `7546fca` and `386dba2` landed arc
steps 3b ("add the ctlogs entry to goldenTrustedRoot") and 3c ("the
flag-clean cosign conformance target") on 2026-06-16. The same day
`b0514b8` marked them LANDED, with those SHAs, in the cross-roadmap
`docs/ROADMAP-STATUS.md` -- but not in the per-arc harness roadmap, which
kept listing 3b and 3c as open steps and was edited once more on 06-17
(`1084790`) without the mark. Four days later the migration commit, stating
"Only open work is migrated; landed work stays in git history", transcribed
3b and 3c from the per-arc file as items 0009 and 0010, flipped them to
`ratified`, and deleted the STATUS file that said they had landed. The two
items sat in the open set for 60 days until `845bade` and `737af88` closed
them on 2026-08-19 with the note that the work "predates the item store --
the item was transcribed ... without noticing the work had landed". The
store inherited the staleness of its source, and the truth it lacked was in
the tree at the moment of transcription, in the file being removed.

The cross-roadmap `docs/ROADMAP-STATUS.md` (`daf2d34`, 2026-06-12) is the
direct ancestor of `_order.md`: a hand-maintained "Execution order
(cross-roadmap)" list over items living in four other files. In its nine
days of life it was touched by 31 commits, most of them status refreshes
("mark item 1 as LANDED" `949db3b`, "correct stale de-seam and ADR-038 index
notes" `fa62a86`, "reconcile roadmap truth" `eab7dbb`). The store removed
the re-typing and the second file, not the need to re-read: the August
amendment wave (section 3.3) is the same refresh, now performed per item.

## 3. Task aging

### 3.1 Full obsolescence: 17 items retired without their own implementation

| Item | Created | Retired | Days | Made obsolete by | Evidence | Mechanism |
|---|---|---|---|---|---|---|
| 0009 ctlogs entry in goldenTrustedRoot | 06-20 `6ba0c61` | 08-19 `845bade` | 60 | Work already landed 06-16 | `7546fca` | transcription lag |
| 0010 flag-clean cosign conformance target | 06-20 `6ba0c61` | 08-19 `737af88` | 60 | Work already landed 06-16 | `386dba2` | transcription lag |
| 0014 upstream osv-scalibr decoupling PR (parked) | 06-20 `6ba0c61` | 06-28 `256b7d0` | 8 | ADR-040 D1 amendment ruled out osv-scalibr on 06-04 | `2ba9ae6` | transcription lag |
| 0015 deploy-path SSH enablement | 06-20 `1d2babc` | 08-25 `105b3f4` | 66 | ADR-051 D5 made SSH a deploy method of its own; D5 applied by item-0105 | `047abe7`, `c863c68` | decision removal |
| 0017 DoT resolver combined IP + hostname | 06-20 `3c173c6` | 06-28 `75d4773` | 8 | Consolidated into item-0049 | `75d4773` | consolidation |
| 0018 DoT resolver port-853 default | 06-20 `3c173c6` | 06-28 `75d4773` | 8 | Consolidated into item-0049 | `75d4773` | consolidation |
| 0019 spec layering Option A (parked) | 06-20 `bb91468` | 06-28 `929e79b` | 8 | Option 2 chosen the same day in ADR-047; landed with item-0037 | `a4f2b07`, `5cb47a7` | alternative recorded as an item |
| 0030 crossval sha256 + loader rework | 06-23 `183b83d` | 06-30 `fa67cbb` | 7 | Loader rework (item-0031) changed the premise; remainder redistributed to 0051/0052/0053/0057 | `9fe9261`, `fa67cbb` | consolidation |
| 0033 transport CUE package split | 06-24 `3e9b818` | 06-25 `8418503` | 1 | Encompassed by item-0036, filed the next day | `82fd7f4` | consolidation |
| 0038 concept tier: DeployTarget and provenance | 06-26 `371640f` | 06-28 `363e2b3` | 2 | Superseded by the wider item-0048 artifact cluster | `21538a2` | consolidation |
| 0043 remove orphaned packed-authority host | 06-27 `d9d2565` | 06-27 `dfc92c7` | 0 | `lane.#Host` retired by item-0040 the same day; "No code change" | `2c0fe06` | side-effect completion |
| 0047 structured IP-plus-port DoT endpoint | 06-28 `f193e88` | 06-28 `75d4773` | 0 | Consolidated into item-0049 | `75d4773` | consolidation |
| 0059 lane.State mutex investigation | 06-30 `6866f34` | 07-05 `f88091c` | 5 | Item-0070's per-step records removed the lock the same day; "Resolved without a dedicated split" | `7360aac` | side-effect completion |
| 0065 lane.DAG exported/unexported mix | 07-02 `e9a9ede` | 07-03 `57bb78a` | 1 | Decomposed into the lane-dag-decomposition arc 0066-0068 | `57bb78a` | consolidation (decomposition) |
| 0100 type the deploy artifacts map key | 07-15 `33b4c16` | 07-18 `8c98677` | 3 | ADR-051 D9 restructured the map; carried inside item-0107 | `9ac0b8d` | decision removal |
| 0109 structure the registry push target | 07-18 `18161ea` | 08-12 `5e60c78` | 25 | Folded into item-0108 ("the target grammar and the push are one change") | `5b08133` | consolidation |
| 0110 push from the control plane | 07-18 `18161ea` | 08-12 `5e60c78` | 25 | Folded into item-0108 | `5b08133` | consolidation |

Four mechanisms account for 16 of the 17:

- **Consolidation** (9 items). The analysis lane files an item, and the next
  planning pass finds it is one facet of a wider change and files that
  instead. `75d4773` states it for the resolver: "Unifies three separate
  proposed items ... Single coherent schema change across primitive/endpoint/
  lane layers ... not three separate reworks." Four of the nine were superseded
  within three days of creation and three more within eight; the two 25-day
  cases (0109, 0110) were decomposition slices of ADR-051 that the analysis
  of item-0108 found to be one change.
- **Decision removal** (2 items, plus the partial cases in 3.4). A ratified
  decision removes or reshapes the surface the item planned to type or
  extend. Item-0015 planned to lift a guard on a method ADR-051 D5 then
  removed; item-0100 planned to type a map key ADR-051 D9 then restructured.
- **Side-effect completion** (2 items). Another item's landing left nothing
  to do; the retire records "No code change" (0043) or "Resolved without a
  dedicated split" (0059).
- **Transcription lag** (3 items). The store inherited entries from prose
  that was already stale (section 2.6 for 0009/0010). Item-0014 is the
  sharper case: the ADR-040 D1 amendment had ruled out osv-scalibr on
  2026-06-04 (`2ba9ae6`), the STATUS file itself said the PR was "no longer
  needed for strike" at `3c173c6^`, and the item was still created, parked,
  and retired eight days later. Its final summary points at
  `docs/D-001-mechanism`, a path that has never existed in the tree; the
  decision lives in `docs/ADR-040-control-plane-sbom-and-keyless-attestation.md`
  under "D1 amendment".

Item-0019 is a fifth kind: created explicitly as "deferred; chose Option 2" on
the day ADR-047 recorded that choice (`a4f2b07`, `bb91468`, both
2026-06-20). It was never work; it was the record of a rejected alternative,
which the ADR already held. The store's own boundary rule ("ADRs and
D-numbered decisions ... live outside this store", `SKILL.md`) was crossed
in the other direction: a decision record was written as an item.

### 3.2 Detection lag is bimodal

The lag between the event that made an item obsolete and the commit that
retired it splits into two populations. Eleven items were retired within three
days of the superseding event -- nine in the same commit or on the same day
(0017, 0018, 0033, 0038, 0043, 0047, 0059, 0065, 0100), and 0109/0110 three
days after the fold commit `5b08133`: the superseding work was the current
planning focus, and the retire rode on it. The others sat in the tail.
Item-0015 was superseded when ADR-051 entered the index on 2026-07-14
(`047abe7`), made structurally pointless when D5 was applied on 07-19
(`c863c68`), and retired on 08-25 -- 37 to 42 days later, in a commit whose
body also finds that "The gate the item named was also wrong: item-0003
rehosts DoT and TLS, while the real prerequisite is the ADR-038 D1 protocol
allowlist extension, which no item owns" (`105b3f4`). Items 0009 and 0010
waited 60 days. Nothing in the workflow reads the tail when the head moves;
section 6.2 traces this to the rule that assigns the retire to "the head of
the next instruction".

### 3.3 Partial aging: amendments

75 content amendments (title, goal, acceptance intent, or body) were made on
47 distinct items before completion; link-only and dependency-only edits are
excluded. The amendments are accretive: 38 lengthened the acceptance intent
and 9 shortened it; 57 lengthened the body and 7 shortened it; the net
addition is 8931 characters of acceptance intent and 41835 characters of body
across the store. Eleven changed the title and fifteen the goal -- the fields
the schema calls the drift-invariant end state. The most-amended items are
0016, 0050, 0079 and 0120 (four amendments each) and 0004, 0052, 0081 (three
each); six of those seven are still open.

Fourteen of the 75 ride on commits whose subject is code or documentation, not
the roadmap (`e497e50` amends 0039 inside the digest collapse, `4ef9b63`
records the ratified forks in 0114 inside the region-map landing, `32bb9ec`
amends 0093 and 0094 inside the lintdocs refactor, `792efce` amends 0120
inside the gengolden refactor). The executor lane amends item content in
passing, although `AI-WORKFLOW.md`, "Roles in the loop", assigns it only the
retire, rank, rescale, restructure, reorder and `_order.md` mutations.

By this reader's classification of the 75 (categories overlap; the count is
by dominant purpose, and the appendix lets it be redone):

| Type | n | What happens | Examples |
|---|---|---|---|
| Decision propagation | 19 | A ratified fork, ruling, or ADR amendment is written into every item it touches | `335ac42` writes the eight type-safety forks into nine items; `1d16250` adds a "Retrospective adjustment" paragraph to 0050, 0052, 0056, 0057; `adbfd62` re-scopes 0057 "onto the ADR-051 D6 remainder" |
| Landing propagation | 17 | A landing elsewhere is recorded in an open item: a clause dropped as settled, a landed cluster noted, a name change carried, a dead link repointed | `e0b4c93` drops the fingerprint clause from 0004 because item-0075 settled it in `ea6e2c5`; `ae4fa89` records in 0050 that `ebf8960` generated the attest cluster; `03ec938` repoints 0016 from `tools/lintfrom`, removed in `a66025c` with item-0068 |
| Follow-up absorption | 13 | A completion-report candidate is folded into an existing item instead of becoming a new one | `a93953a` absorbs item-0114's candidates into 0050, 0052, 0081, 0111, 0120; `9828bf0` widens 0016 to required-ness from item-0011's report "because it wants the same machinery"; `e18d8a4` folds the lintdocs plugin adoption into 0093 |
| Measurement replaces assumption | 13 | The analysis lane re-reads the tree or runs a check and rewrites the item to what it found | `2ae5fe8` rewrites 0007 after a hand run of `cosign verify-attestation`; `2780558` finds `sanitizeForLog` "implemented twice, not once" and rewrites 0089's clause, which "was satisfiable by fixing the cmd copy alone"; `85a6c38`, `15e69d6`, `9c2fc16` amend 0004, 0079, 0080, 0084, 0086 "from the mediator strand read" and "from a typeflow run" |
| Split and re-scope at ratification | 9 | Scope moves between items or is narrowed to what can be ratified | `1d186eb` splits the image-from resolver out of 0066 into 0069; `02d0a03` re-scopes 0016 to a mandatory CUE lint; `f556510` rewrites 0120 "to survive the Makefile removal" scheduled by items behind it |
| Executor-recorded state | 4 | The landing commit itself records ratified forks or progress in the item | `4ef9b63` (0114), `e497e50` (0039), `425f985` (0084), `5935e3f` (0136) |

Two of these types are the same phenomenon as section 3.1 at a finer grain.
Landing propagation is partial obsolescence: a clause is dropped because
another item did the work (0004 lost its fingerprint clause to 0075, and the
commit body says "Leaving the clause in item-0004 would claim work another
item owns"). Measurement-replaces-assumption is the discovery that an item
was written against a tree it did not describe (0089's single
`sanitizeForLog`, 0007's assumed verification gap, 0133's harness Makefile
that "is not the thin wrapper item-0097 budgets for").

Two amendments are worth singling out because they age other items' claims
about items. `85c4f3a` corrects a claim in item-0052 that item-0079 depends
on it, tracing the wrong claim to "section 10 of the dual type-safety audit
retrospective, which is append-only history and is corrected in its own
annotation". `dc83c97` adopts 20 `depends_on` edges after "per-edge
verification against item bodies, ADRs, and code": 12 of the 32 proposed
edges were dropped as "topical affinity, already-satisfied prerequisites, or
pointed backwards". The planning graph itself had aged; the verified edges
surfaced one real scheduling gap (item-0133 unscheduled although item-0097
depends on it).

The anchors themselves hold up well. Of 70 distinct commit tokens cited
across all 140 item files, 69 resolve in the published history. The one that
does not is in item-0103, "zero consumers verified at 46d0b5d": a
verification pinned to a tree that never became a commit on any published
ref, so the claim cannot be re-checked -- the same failure class
`AI-ORCHESTRATION.md` describes for before-snippets taken from "a working
copy or an upload that predates the pin".

### 3.4 Executed narrower than written

Five executed items landed less than their text promised, and the final
summary carries the difference:

- **0076** "lane contract typing cluster: keys, references, defaults" --
  "Three of the six original acceptance clauses landed at e0e8afbc7b ... The
  goal and acceptance_intent above were reduced to those three before this
  retire, because the other three were rerouted" (`33b4c16`, which also
  creates item-0100 for one of them).
- **0107** "Restructure deploy artifacts into one pushed image plus SBOM
  regions" -- "Landed as f872d435, leaner than the title ... The SBOM-region
  decomposition in the original goal did not land: during ratified analysis
  the reference model was reconceived" (`695ce6d`); the decomposition became
  item-0114 the next day (`78ea223`).
- **0088** "Type transport.DialTCP on endpoint.Address" -- "DialTCP retyped to
  netip.AddrPort (not endpoint.Address) per the executed instruction"
  (`ce77d2c`). The title still names the type the instruction chose not to
  use.
- **0091** "Decide the visibility of generated enum constants" -- "genenums
  already exports constants ... internal/container was already clean"
  (`3d5310d`); the decision the title asks for had been made by the tree.
- **0057** "Decide the deploy target naming, type, and namespace" -- re-scoped
  once when ADR-051 D6 overtook it (`adbfd62`), then closed by producing D10,
  which removed the target instead of naming it (`1472668`, `56b257e`); the
  removal was executed by items 0106 and 0113.

### 3.5 What ages, in one sentence each

- Items age fastest right after creation: the next planning pass consolidates
  them (six of the 17 retirements within three days of creation).
- Items age slowest in the tail: obsolescence is detected when the item's
  turn comes or in a grooming pass, not when the superseding event lands.
- Open items grow while they wait: the field that should state a
  drift-invariant intent accumulates measured site facts, absorbed
  follow-ups, and dated amendments, and the six longest acceptance intents
  in the store are all open.
- Claims items make about other items, and the dependency edges between
  them, age like the items themselves (`85c4f3a`, `dc83c97`).
- The store inherited aging from the prose era and did not add a mechanism
  against it; the August wave is the prose era's status refresh, per item.

## 4. Task explosion

### 4.1 Where the 140 items came from

| Origin | Items | Notes |
|---|---|---|
| Decision or retrospective batch | 62 | ADR-047 (0019-0025), ADR-048 (0037-0043), CUE contract review (0051-0057), the 2026-07-07 retrospective (0071-0084), the ADR-049 ruling (0086-0092), the beta cut (0094-0097), ADR-051 (0101-0113), ADR-052 (0137-0140) |
| Stated follow-up of one item | 36 | Body or creation commit names the item it came from (section 4.2) |
| Transcribed from the prose roadmaps | 18 | 0001-0018 |
| Free analysis proposal | 12 | Filed from the analysis lane's own reading, no single item or decision named (0031-0036, 0047, 0048, 0058, 0060, 0061, 0099) |
| Review or audit finding | 5 | 0062-0064 ("Found at 3db7843"), 0123 ("found by the adversarial audit ... at 41c44c4"), 0132 (incident on the running host) |
| Other | 7 | 0028 (ADR-046 retrospective), 0044 (residue of the 0037 rename), 0049 (consolidation of three items), 0085 ("Carved out of the fork-C ratification"), 0122 (the follow-up ADR-035 named when it removed the host scratch), 0129 and 0130 (no origin stated) |

The batches are the volume; the follow-ups are the churn. The two classes
behave differently in the store: batch items wait in `_order.md` and age
(section 2.3), follow-up items are ratified and executed within days.

### 4.2 Fan-out from completed items

Of the 72 executed items, 19 have at least one new item that names them as
its origin, one more (0011) amended an existing item instead, and item-0114
additionally amended five existing items in one commit. The table lists
every stated edge with the commits that created it; where the only link is
a shared commit, the row says so.

| Source item (closed) | New items | Amended items | Stated link |
|---|---|---|---|
| 0001 ADR-046 output model (`4837075`) | 0026, 0027 (`5af6743`) | -- | commit body: "Two items surfaced while wiring item-0001"; 0027: "Surfaced while wiring item-0001" |
| 0024 scalar consolidation (`2a34714`) | 0029, 0030 (`b2c696d`, `183b83d`) | -- | "Split out of item-0024" in both bodies |
| 0034 internal API type-cleanliness (`2051902`) | 0050 (`af7e58b`) | -- | 0050: "The item-0034 Identifier cascade ... propagated a named type through the hand-written attestation and predicate structs" |
| 0040-0042 endpoint arc | 0045 (`734bafd`), 0046 (`9a00dde`) | 0041 (`dfc92c7`) | 0045: "during the ADR-048 concept-tier / endpoint @go work"; 0046: "Follow-on to item-0042" |
| 0050 CUE coverage audit (open) | 0059 (`6866f34`) | -- | "Surfaced during the 0050 audit and flagged by the operator as a follow-up" |
| 0058 migrate-to-CUE linter (`932406f`) | 0065 (`e9a9ede`) | -- | "Surfaced by the coverage linter (item-0058)" |
| 0065 (retired into the arc) | 0066, 0067, 0068 (`57bb78a`) | -- | final summary "Superseded by lane-dag-decomposition arc" |
| 0066 step-id index (`7981061`) | 0069 (`1d186eb`) | 0066 | "Split out of item-0066" |
| 0069 image-from resolver (`5f7e488`) | 0070 (`d3ff624`) | 0069 | 0070 filed in the commit that ratifies 0069; its body records a "Discovery (at the time of writing)" against the state "removed by item-0069" |
| 0073 linttypeflow (`dd8fe3c`) | 0093 (`42b0d33`), 0094 (`d2be51e`) | 0084 (`425f985`) | 0093: "Closes the measured duplication between the two Go-type linters (comparison A of the tooling review)"; 0094: "The CUE-side analogue of item-0093" |
| 0075 fingerprint typing (`3a75009`) | 0098 (`2c166e9`) | -- | "Defect surfaced by item-0075" |
| 0076 lane typing cluster (`33b4c16`) | 0100 (`33b4c16`) | 0079 (`33b4c16`) | "Register row R-05, rerouted out of item-0076" |
| 0107 deploy artifacts restructure (`695ce6d`) | 0114 (`78ea223`) | 0108 (`5b08133`) | 0107: the decomposition "did not land ... reconceived"; 0114: "Owns the D9 promise item-0108 defers" |
| 0108 registry sealing point (`5e60c78`) | 0115, 0116, 0117 (`28f3483`) | -- | commit subject "item-0108 follow-ups" |
| 0113 remove deploy target (`0c54298`) | 0118 (`82050ef`) | -- | "Documentation drift left by e7d2efd (item-0113)" |
| 0114 D9 region map (`0b44659`) | 0124 (`f4521c7`), 0127, 0128 (`e7dd200`) | 0050, 0052, 0081, 0111, 0120 (`a93953a`) | "Absorbed from the item-0114 completion report" in each of the five; `4ef9b63` body: "the item-0124 anchor question stays owned there" |
| 0116 live registry-deploy itest (`549b83c`) | 0119, 0120 (`993db12`) | 0116 | commit "correct item-0116 acceptance; add items 0119 and 0120" |
| 0120 golden generator (`418aa5e`) | 0121 (`41c44c4`), 0131 (`0a8a923`) | 0120 | 0131: "Deferred out of the golden-generator rework, which could not carry it"; 0121 filed in the commit that extends 0120 |
| 0122 host-filesystem round-trips (`0d9cd81`) | 0125 (`0d9cd81`), 0126 (`e7c5939`) | -- | 0125: "Item-0122 removed every production import of go-containerregistry's layout package ... leaving three ratified test-scaffolding exclusions"; 0126 links 0122, filed the same day |
| 0119 fail-fast itest gate (`ecf3066`) | 0135 (`6e15154`), 0136 (`f3918aa`) | -- | 0136: "Surfaced by item-0119"; 0135: "the way item-0119 removed for the env-gated integration tests" |
| 0011 SCT enforcement (`9828bf0`) | -- | 0016 (`9828bf0`) | "Absorbed from the item-0011 completion report: the second axis" |
| 0136 mediator cancellation (`a95de9c`) | 0137-0140 (`6fba150`) | 0136 (`5935e3f`) | ADR-052 adopted the same day (`6e5833a`); 0140: "Hard-sequenced after item-0136, which shares the capsule surface" |
| 0097 retire the harness Makefile (open) | 0133, 0134 (`548eaaf`) | -- | 0133: "The harness Makefile is not the thin wrapper item-0097 budgets for" |

Three fan-outs stand out.

**Item-0114** is the clearest single explosion: one landing (`4ef9b63`)
produced three new items and five amended ones, eight touch points in three
roadmap commits on one day (`f4521c7`, `e7dd200`, `a93953a`). The item's
own final summary reads "Absorbed into items 0050, 0052, 0081, 0111, 0120"
(`0b44659`) -- the sentence describes where its follow-ups went, not what it
landed, so the record of the store's largest executed change in August is
the record of its residue.

**Item-0108** shows the other shape: an arc slice whose analysis first
absorbed two siblings (0109, 0110 folded in by `5b08133`, 84 files
+710/-744 at landing) and then emitted three follow-ups (`28f3483`). The
follow-ups themselves fanned out: 0116 to 0119/0120, 0120 to 0121/0131,
0119 to 0135/0136, 0136 to the ADR-052 arc.

**Item-0065 to item-0070** is a chain run at full speed: the coverage linter
(0058, done 07-02) surfaced 0065 the same day; 0065 was decomposed into
0066-0068 the next day; 0069 was split out of 0066 the same day; 0070 was
filed with 0069's ratification on 07-04; all six were closed by 07-06. Five
generations in four days, none of them older than the work that produced them.

### 4.3 Fan-out from decisions and retrospectives

| Source | Date | New items | Amended items |
|---|---|---|---|
| ADR-047 spec layering (`a4f2b07`) | 06-20 | 0020-0025 (`ef1bc70`), 0019 as the parked alternative | -- |
| ADR-048 primitive/concept tiers | 06-26/27 | 0037-0039 (`371640f`), 0040-0043 (`d9d2565`) | 0036 retired, 0041 realigned |
| CUE contract review | 06-30 | 0051-0057 (`768b60a`) | 0004 ("fold B2 into 0004"), 0050 |
| Retrospective 2026-07-07 dual type-safety audit | 07-07 | 0071-0084 (`e1ff84d`) | 0050, 0052, 0056, 0057 ("Retrospective adjustment", `1d16250`) |
| Type-safety forks A-H ratified | 07-09 | 0085 (`335ac42`) | nine items (`335ac42`) |
| ADR-049 ruling of the disputed set (item-0072) | 07-09 | 0086-0092 (`ce859ca`) | 0074 (`ac6ce17`) |
| Beta cut ratified | 07-11 | 0094-0097 (`d2be51e`) | 0063, 0064 (`d2be51e`) |
| ADR-051 deploy as sealing point | 07-14 to 07-19 | 0101-0112 (`18161ea`), 0113 (`10d0d22`); later 0123 (`bd5712c`) | 0057 (`adbfd62`), 0107 (`c50d37b`); retired 0100 (`8c98677`), 0015 (`105b3f4`) |
| Adversarial audit of the sealing path at `41c44c4` | 08-15 | 0123 | -- |
| ADR-052 lock-free execution (`6e5833a`) | 08-23 | 0137-0140 (`6fba150`) | -- |

Decisions are the larger generator, and they generate twice. First as a
batch of items that implement them; then, because a ratified decision
reshapes the surface other items were written against, as amendments to and
retirements of items filed before the decision (section 3.1, "decision
removal"). ADR-051 is the fullest example: eleven items filed from it,
two items re-scoped, two retired as moot, and one defect item filed against
it four weeks later by an adversarial read of its own sealing path (0123,
"ADR-051 decides the subject three times").

### 4.4 Chains and depth

Following the stated edges backward, the longest chain in the store is five
generations: ADR-051 -> 0108 (registry sealing point) -> 0116 (live registry
itest) -> 0119 (fail-fast gate, retargeted at the harness) -> 0136 (mediator
cancellation) -> 0137-0140 (the lock-free arc). Every hop is a discovery
made by executing or verifying the previous one, and every hop is dated
within 42 days of the ADR. The second-longest, 0058 -> 0065 -> 0066 ->
0069 -> 0070, ran in four days (section 4.2).

The deepest chain -- an ADR to a live test to a gate to an incident to a
new ADR -- is the mechanism the workflow calls its follow-up channel,
operating as designed (`AI-ORCHESTRATION.md`, "The
follow-up channel"). None of the five hops is scope creep; each is a defect
or a gap that the previous step made observable.

### 4.5 Absorption as the counter-move

The store does not always answer a completion report with new items. Five
of item-0114's candidates were written into existing items in one commit
(`a93953a`) rather than filed; item-0011's report widened item-0016
"because it wants the same machinery: one CUE lint rule wired mandatorily
into the build gate" (`9828bf0`); the lintdocs plugin adoption was folded
into item-0093 (`e18d8a4`). Thirteen of the 75 amendments in section 3.3
are this move.

Absorption bounds the item count and moves the growth into the items. The
single commit `a93953a` added 851 characters of acceptance intent and 2428
characters of body across five open items; `9828bf0` added 781 and 1390 to
item-0016; `e18d8a4` added 366 and 1474 to item-0093. Every one of those
items is older than the follow-up absorbed into it, and three of them
(0016, 0050, 0052) are among the seven most-amended items in the store. The
explosion is bounded in count by being converted into accretion, which is
section 3.3's partial aging.

### 4.6 Net effect

Explosion is real at the source and absorbed in the aggregate. Creation fell
from 61 to 52 to 27 items per month while closure held at 31, 32, 26; the
open set has been flat at 50 to 56 since 2026-07-20 (section 2.2). What the
fan-out changed is the composition of the open set, not its size: the
fast-lane items it produces are executed within days, while the batch items
that set the level in June and July wait, accrete, and age. The store is not
growing; it is getting older and denser.

## 5. Patterns

Each pattern below is stated once with its evidence section; section 6 maps
the patterns to the rules that produce them.

**P1 -- Two speeds, one order file.** `_order.md` is documented as "the
cross-arc truth for what runs next" (`roadmap/_order.md` header), and eleven
commits move a freshly ratified item to its top. What runs next is, in
practice, the newest discovery; the batch items scheduled earlier wait. The
order file is written as a queue and executed as a stack. (2.3, 2.4)

**P2 -- Discovery precedes closure.** Follow-up items are filed before or in
the commit that retires their parent, never after: 0026/0027 (`5af6743`)
before 0001's retire (`4837075`) on 06-21; 0029/0030 on 06-23 and 0024 done
06-24; 0050 on 06-29 and 0034 done 06-30; 0098 on 07-11 and 0075
done 07-12; 0115-0117 on 08-11 and 0108 done 08-12; 0119/0120 on 08-14 and
0116 done 08-15; 0118 with 0113, 0131 with 0120, 0136 with 0119, 0125 inside
the retire commit of 0122 (`0d9cd81`). The completion report is read while
the change is still being landed, and the retire commit is where the store
learns what the report found. (4.2)

**P3 -- Decisions generate twice.** A ratified ADR or fork produces a batch
of implementing items, then produces amendments and retirements of the items
written before it against the surface it reshaped. ADR-051: eleven items
in, two re-scoped, two retired moot, one defect item back against it. (3.1,
4.3)

**P4 -- Items age fastest at birth and slowest in the tail.** Six of the 17
retirements happened within three days of creation, in the next planning
pass; the items that outlived their premise by weeks (0015: 37-42 days,
0009/0010: 60) were unscheduled tail items nobody re-read. Detection lag is a
function of distance from the current focus, not of the item's age. (3.1,
3.2)

**P5 -- Accretion instead of retirement.** Amendments lengthen (38 of 75
lengthen the acceptance intent, 9 shorten it; net +8931 acceptance and
+41835 body characters), and absorption turns would-be new items into
paragraphs of old ones. The six longest acceptance intents in the store are
open items; 0016 grew from 352 to 1960 characters over four amendments while
waiting 67 days. The field defined as drift-invariant intent carries dated
site facts, absorbed candidates, and corrections of its own earlier claims.
(3.3, 4.5)

**P6 -- `done` is overloaded and the final summary carries the semantics.**
Executed, superseded, absorbed, moot, retroactively closed, and resolved as a
side effect are all `done` under `roadmap/completed/`; the distinction lives
in free text. That text sometimes records the residue rather than the
landing (0114: "Absorbed into items 0050, 0052, 0081, 0111, 0120", for a
change that landed as `4ef9b63`), sometimes a title the instruction did not
implement (0088), and once a path that never existed (0014,
`docs/D-001-mechanism`). (1.3, 3.1, 3.4)

**P7 -- Decision items age by construction.** Items titled "Decide",
"Investigate", or "Adjudicate" (0057, 0059, 0072, 0091, 0128) have their
scope fixed by a decision that is made outside the store: the outcome is an
ADR amendment (0057 to D10, 0072 to ADR-049 and the rulebook), the discovery
that the tree already decided (0091), or resolution as a side effect (0059).
Item-0019 is the inverse, a rejected alternative filed as an item on the day
the ADR rejected it. The store's own boundary ("Never touch ADRs,
D-decisions", `SKILL.md`) is respected in the writing direction and crossed in
the reading direction: items carry decision state that the ADR is the single
source for. (3.1, 3.4)

**P8 -- Claims about items age like items.** A retrospective adjustment in
0052 asserted a dependency on 0079 that a later read found to be "a merge
neighbourhood, not a blocker" (`85c4f3a`); 0015's stated gate pointed at
0003 when "the real prerequisite is the ADR-038 D1 protocol allowlist
extension, which no item owns" (`105b3f4`); 12 of 32 proposed `depends_on`
edges were dropped on verification (`dc83c97`); 0016 pointed at a linter
that 0068 had deleted (`03ec938`). The cross-references between items are
authored by the same reading that authors the items, and drift at the same
rate. (3.3)

**P9 -- The executor writes item content in passing.** Fourteen of 75
amendments ride on code or documentation commits, including the recording of
ratified forks inside the landing commit (`4ef9b63`, item-0114) and
acceptance edits inside refactors (`e497e50`, `792efce`, `32bb9ec`). The
role split in `AI-WORKFLOW.md` assigns item creation to the analysis lane
and only retire/rank/order mutations to the executor; content amendment is
assigned to nobody and done by both. (3.3)

**P10 -- Grooming comes in waves, and the wave is the prose-era refresh.**
Amendments cluster: the consolidation wave of 06-27 to 06-30 (0049, 0048,
the CUE contract review), the decision-propagation wave of 07-08 to 07-11
(`335ac42` nine items, `1d16250` four, `01e7b02` three), and the measurement
wave of 08-19 to 08-26 (23 amendments on 18 items, each commit body opening
with what was measured against the live tree). The last wave coincides with
the first appearance of `Claude Opus 5` co-author trailers in store commits
(`30944c7`, 08-19) -- a correlation this reader records without a causal
claim. Between waves the tail is not read. The prose era needed 31 commits
in nine days to keep one STATUS file true; the store needs the same
re-reading, now spread across 51 files. (2.6, 3.3)

## 6. Rules that contribute systematically

The workflow's rule files are explicit that every imperative was adopted
after a measured failure (`AI-WORKFLOW.md`, opening; `AI-ORCHESTRATION.md`,
"Evidence base"). The rules below are quoted from the audited tree and
mapped to the patterns of section 5. Two findings frame the section: the
explosion side is produced by rules that exist and work as designed; the
aging side is produced by rules that exist for a different purpose, plus
rules that do not exist.

### 6.1 Rules that generate follow-ups (explosion, by design)

| Rule | Where | What it says | What it produces |
|---|---|---|---|
| R1 Stop and report | `AGENTS.md`, "Code is liability", rule 4 | "A correct but out-of-scope improvement is reported as a follow-up candidate, never implemented in passing." | Every executed item is a candidate source. P2. |
| R2 Mandatory report section | `AGENTS.md`, "Completion report" | "Follow-up candidates -- every correct-but-out-of-scope improvement encountered ... A missing section is a gate failure." | The channel cannot be skipped; `none` must be written. P2. |
| R3 Candidates become items | `AI-WORKFLOW.md`, "Anti-initiative is structural, not advisory" | "Anti-initiative without an exit is lossy ... the author turns those candidates into roadmap items." | 36 items state a parent item; 13 amendments absorb candidates. 4.2, 4.5. |
| R4 Sibling closure and deferral owners | `AI-WORKFLOW.md`, "Authoring clauses", 2 and 4 | Every sibling "either in scope or named as a deferral with its follow-up item id"; "A deferral without an owner is a defect of the change introducing it." | Items created at authoring time, before execution, to own a deferral: 0098 (descoped from 0075, `e0b4c93` body), 0111 ("kubernetes cardinality deferred to item-0111", ratified forks recorded in item-0114's body), 0124 ("the item-0124 anchor question stays owned there", `4ef9b63`), 0125 ("three ratified test-scaffolding exclusions"), 0131 ("Deferred out of the golden-generator rework"). |
| R5 Domain verification before retype | `AI-WORKFLOW.md`, "Authoring clauses", 3 | Sentinels and composite values "block the retype until they are removed or the target design is widened by ratified decision." | Prerequisite items filed ahead of typing items: 0060 ("the attestation signing canonicalization prerequisite (C-first)", `31b5421`), 0083 ("Eliminate in-band grammar sentinels"), sequenced before the typing items it unblocks. |
| R6 Retrospectives write into the store | `AI-WORKFLOW.md`, "Planning state lives in the roadmap item store" | "when one enumerates open work under its own labels, the fix is to write it into the store." | The largest batch: 14 items from one retrospective (`e1ff84d`), plus four "Retrospective adjustment" amendments (`1d16250`). 4.3. |
| R7 Decisions before instructions | `AI-WORKFLOW.md`, "Decisions are ratified before instructions exist" | "An instruction never carries an unratified schema choice." | Decision items (0057, 0072, 0128) and the batch each decision produces (ADR-047, -048, -049, -051, -052). P3, P7. |
| R8 One concern per PR | `AI-WORKFLOW.md`, "Cluster by risk, not by finding order" | "Substantive changes -- schema, types, behavior -- stay separate and cautious, one concern per PR." | Arc decomposition into item batches: 11 slices of ADR-051 (`18161ea`), 7 of ADR-049 (`ce859ca`). 2.5. |
| R9 The follow-up channel as the fix for M2 | `AI-ORCHESTRATION.md`, "The follow-up channel", "The mechanism taxonomy" | The candidates "went into a completion report, the report went into a transcript, and the transcript was compacted ... nothing in the system remembered." | The intent is stated: item creation is the designed exit of anti-initiative. The explosion of section 4 is this rule succeeding. |

R1 to R4 and R9 are one mechanism seen from four places. It was adopted to
stop candidates from being lost (M2) and it stops them: in the store, every
executed item that surfaced work has a child or an amendment that names it
(P2), and the deepest chain in the store is five generations of exactly this
(4.4). The finding is not that the rules over-produce; it is that they
produce into a store whose other rules do not consume.

### 6.2 Rules that produce aging (for a different purpose)

| Rule | Where | What it says | What it produces |
|---|---|---|---|
| A1 Retire rides the next instruction | `AI-WORKFLOW.md`, "Roles in the loop" | "a retire rides at the head of the next instruction, a reorder rides with the work that reorders it" | The store learns that an item is obsolete only when an instruction is authored near it. Same-day detection for items in focus, 37 to 60 days for the tail (0015, 0009, 0010). P4. |
| A2 Drift-invariant content, by exclusion | `AI-WORKFLOW.md`, "Planning state lives in the roadmap item store"; `references/schema.md`, "Why byte-exact contracts are excluded" | "The store holds only drift-invariant state ... never byte-exact snippets, file-and-edit lists, or grep gates"; "a stored item carrying a stale snippet is worse than no item". | The rule bans one class of drift-variant content and is silent on the rest. Items carry measured site facts ("both sanitizeForLog copies", `2780558`; the seven affected definitions written into 0016 "so the classification work starts from evidence rather than from a re-survey", `9828bf0`), and those facts drift. 34 items changed acceptance length; the field that names the risk has no re-validation attached. P5. |
| A3 One-time ratification, one exit | `references/schema.md`, "Status model and the ratification gate"; `SKILL.md`, "Status gate" | "The status flip is bookkeeping that rides along with that merge"; states are `proposed`, `ratified`, `done`. | Ratification does not expire and has no re-check: nine items ratified on 2026-06-20 are still `ratified` on a tree 353 commits later. Superseded items exit as `done`; the outcome is free text. P6. |
| A4 Removal is the default; ADRs are append-only and outside the store | `AI-WORKFLOW.md`, "Removal is the default resolution", "Decisions are ratified before instructions exist"; `SKILL.md`, "ADR boundary" | "removal is the default"; ADRs "live outside this store ... never touched here". | Decisions remove the surfaces older items were written to type or extend, and the direction of reference is one-way: the item links the ADR, nothing links the ADR to the items it moots. ADR-051 D5/D9/D10 mooted 0100 and 0015 and re-scoped 0057 and 0107; 0015's lag was 37 to 42 days. P3. |
| A5 No item ids in code | `AGENTS.md`, "Code style", "Comments are self-contained"; `AI-WORKFLOW.md`, "Code comments never leak the workflow's transient vocabulary" | "no roadmap ids, instruction references, historical narrative" in comments. | Correct for the code, and it means a landing cannot name the items it affects; the only mechanical bridge is `links:` in the item, which is a list of paths (renamed in `66c8a58`, dead in `03ec938`) that no gate checks (below). P8. |
| A6 Absorption keeps the active set small | `SKILL.md`, "The store layout" ("done items are moved here, keeping the active set small"); practice in `a93953a`, `9828bf0`, `e18d8a4` | Not a written rule: the practice, in the ratifying commits, of folding candidates into existing items "because it wants the same machinery". | Bounds the item count and converts explosion into accretion on the oldest items. P5, 4.5. |
| A7 Migration copied the prose's open set | `3c173c6` body: "Only open work is migrated; landed work stays in git history and the ADRs." | A one-time rule that trusted the per-arc prose to be current. | Three items born stale (0009, 0010, 0014), one of them 16 days after its decision, while the STATUS file that said LANDED was deleted in the same commit. 2.6, 3.1. |
| A8 The analysis lane grounds at a pin | `AI-WORKFLOW.md`, "The analysis model grounds by reading, not by running"; "A before-snippet is taken from the pinned tree itself" | Grounding is pinned for instructions, which are ephemeral. | Items are also authored against a pin ("Found at 3db7843", "At 3db7843 the README pins", "verified at 46d0b5d") and are durable; the pin is the last verification anchor and the schema has no field for it, so age-since-verification is not queryable. P8, 3.3. |

### 6.3 Rules that do not exist

- **No terminal state but `done`.** Superseded, absorbed, moot, retroactive,
  and side-effect closures are indistinguishable from executed ones without
  reading the final summary (17 of 89). P6.
- **No amendment rule.** `update` exists as a command; nothing in `SKILL.md`,
  `schema.md`, `AI-WORKFLOW.md`, or `AGENTS.md` says who amends item content,
  when, or how. The "Amended YYYY-MM-DD at SHA" paragraph appears first on
  2026-08-19 (`30944c7`, `2780558`, `2ae5fe8`) as an unwritten convention;
  before that, amendments rewrote fields in place. P9, P10.
- **No re-validation trigger.** Nothing runs when an ADR lands, when a
  removal lands, or when an item is retired, to re-read the open items that
  link the affected surface. None of the three grooming waves was
  triggered by a written rule (P10); the tail between them was not read
  (P4).
- **No staleness signal.** No field records when an item was last verified
  against the tree, so neither `list` nor `deps` can say which items are
  stale. Age since creation is derivable from git; age since verification is
  not.
- **No link check.** `deps --check` validates `depends_on` (dangling edges,
  cycles, order, status inversion) and `SKILL.md` calls it "the natural CI
  check on a roadmap PR" -- but nothing wires it: `make check`, the
  repository's only workflow (`.github/workflows/update-bootstrap-hash.yaml`),
  and `lane.yaml` do not run it, and it does not validate that the paths in
  `links:` exist. The tree has an index check for ADRs
  (`docs/AI-REVIEW-AND-RETROSPECTIVES.md`, "Snapshot hygiene"; landed as the
  `adrindex` analyzer of item-0095) and none for the store. 0016's link to
  `tools/lintfrom` died on 2026-07-05 (`a66025c`) and was found on 2026-08-25.
- **No tail policy.** `_order.md` has a head; nothing addresses its end.
  There is no rule for what happens to an item that stays `ratified` and
  unscheduled for N days (0013 and the parked arc, the nine first-day items,
  0015 until `105b3f4`). P1, P4.
- **No final-summary shape.** `schema.md` says the executor "writes the
  final summary" and nothing about its content; the results range from a
  landing commit plus diffstat (0108) to one clause (0058, "Completed CUE
  coverage rule enforcement with mandatory linter"), a residue map (0114),
  or a nonexistent path (0014). P6.

The asymmetry is the finding. The workflow built a channel from execution
back to planning (R1-R4, R9) after measuring what its absence cost (M2, M3).
It did not build the channel from planning back to execution: from a landing
or a decision to the open items it aged. The prose era paid that cost as 31
STATUS commits in nine days; the store pays it as waves.

## 7. Candidates for confirmation

These are candidates in the sense of `docs/AI-REVIEW-AND-RETROSPECTIVES.md`:
a list to verify against the live tree and the operator's intent, not
changes to apply. None is a roadmap item; if any is adopted, the placement
rule in `AI-WORKFLOW.md` ("Where a rule lives") decides where its imperative
goes, and the item store decides its work. Each names the finding it
answers, the shape it could take, and what it would cost or risk.

**What not to change.** The follow-up channel (R1-R4, R9) is working as
designed: candidates become items or amendments within a day of the landing
that surfaced them (P2), and the longest chain in the store is a sequence of
real defects made visible one by one (4.4). The candidates below add the
return path the channel lacks; none of them narrows it.

**C1 -- A terminal outcome distinct from executed.** Answers P6 and the
executed-versus-retired ambiguity of 1.3. Shape: either a fourth status
(`withdrawn`, reached from `proposed` or `ratified`, moved to `completed/`
like `done`) or a `resolution:` field on done items with a closed vocabulary
(executed, superseded, absorbed, obsolete, retroactive). The final summary
keeps the prose; the field makes it queryable (`list --status done
--resolution superseded`). Cost: one schema field, one script change, and a
one-time classification of the 89 done items, which appendix A already
contains for this reader's reading. Risk: a vocabulary that is too fine
invites arguments at retire time; appendix A needed seven labels, and five
would have done.

**C2 -- A verification anchor on every open item.** Answers P5, P8, A8.
Shape: a `verified_at: <sha>` field written whenever an item's content is
confirmed against the tree (creation, ratification, any amendment), and a
`list --stale N` or `deps --stale` query that reports items whose anchor is
more than N commits behind HEAD. The August amendments already carry the
anchor in prose ("Amended 2026-08-26 at dc83c97"); the field makes the same
fact machine-readable. Cost: one field, and the discipline to update it
only after a real re-read. Risk: the anchor is a declaration, and a
declaration that is refreshed without a read is worse than none -- pair it
with C3 so the refresh has an occasion.

**C3 -- A follow-back channel: landings and decisions name the open items
they age.** Answers A1, A4, P3, P4, and the 37-60 day detection lags of
3.2. Shape, two halves. Executor side: the completion report's mandatory
sections gain a third, "Open items affected", listing every open item whose
`links:` name a file, package, or ADR the change touched, each marked
unaffected / narrowed / mooted -- or `none`, derived mechanically from a
grep of `links:` over the diff's paths, so the list is an observation rather
than a recollection. Author side: when an ADR or D-decision is recorded, the
same session re-reads the open items that link that ADR or the surface it
reshapes, before authoring the implementing batch. What it would have
caught: 0015 on 2026-07-14 instead of 08-25; 0016's dead link on 07-05
instead of 08-25; 0004's fingerprint clause on 07-12 (`ea6e2c5`) instead of
08-26. Cost: one grep per landing and one read per decision. Risk: the
executor writes `none` reflexively; the mechanical derivation from `links:`
is what keeps it honest, which is why C6 matters.

**C4 -- Bound what an open item may carry.** Answers P5 and A2. Shape:
`goal` and `acceptance_intent` state the end state only, in the sense
`schema.md` already gives them; measured site facts, absorbed candidates,
and corrections go into the body under dated, anchored paragraphs
("Measured at <sha>", "Absorbed from item-NNNN at <sha>"), which the
August wave already does. The point is that ratification was granted on the
short fields, and a body paragraph does not re-open it; a change to the
short fields does. Cost: rewriting the six longest open items once (0016,
0080, 0050, 0126, 0084, 0079). Risk: the body becomes the new accretion
site; that is acceptable if the body is what `list` does not print.

**C5 -- Assign content amendment to a lane.** Answers P9. Shape: either
amendments are the analysis lane's only, delivered as patches like item
creation, and the executor's landing commit may add only a dated "Landed"
paragraph and the retire; or the executor may amend, and the amendment is
listed under Deviations in the commit body so `git log` carries it. Fourteen
amendments in this record ride on code commits without either. Cost: one
sentence in "Roles in the loop". Risk: none visible; the choice between
the two shapes is the operator's.

**C6 -- Wire the store's own checks into the gate.** Answers the "No link
check" finding of 6.3. Shape: `deps --check` extended to verify that every
path in `links:` exists at HEAD (ADR ids and item ids resolve already), and
run from `make check` or from the dogfooded lane item-0063 plans, the way
the ADR index is checked. Cost: a few lines in `roadmap.py` and one gate
line. Risk: renames of linked files fail the gate until the item is
repointed -- which is the intended effect (`66c8a58`, `03ec938` were both
manual discoveries).

**C7 -- A shape for the final summary, and a rule for anchors.** Answers
P6, 0114, 0014, and the single uncheckable anchor in 0103. Shape: the final
summary names the landing commit(s) and states what landed and what did not
(the 0076 and 0107 summaries are the model); follow-up routing belongs in
the absorbing commit's message and the children's bodies, where it already
is; and every commit-like token in an item file must resolve in the
published history, checked by C6's gate. Cost: two sentences in
`schema.md`. Risk: none visible.

**C8 -- A tail policy, or the decision that there is none.** Answers P1 and
P4. Shape: an operator checkpoint for items that have been `ratified` and
unscheduled, or scheduled below position N, for more than M days -- re-ratify
against the current tree (updating C2's anchor), park explicitly (the
`parked` arc exists; 0013 and 0124 use it), or withdraw (C1). Cost: one
operator pass per interval; the August wave shows the pass costs about a
week of analysis sessions for 18 items. Risk: ratification churn if M is
small; the record suggests the tail changes only when a decision lands, so
tying the checkpoint to decisions (C3) rather than to a calendar may be
enough.

**C9 -- Decide whether decision-shaped work belongs in the store.** Answers
P7 and the item-0019 boundary crossing. This is a question rather than a
proposal: the store's constitution keeps ADRs out and planning state in, and
"Decide", "Investigate", and "Adjudicate" items sit on the line. If they
belong in the store, an `execution_profile.class: decision` (or a `decision`
arc) would make their expected closure -- an ADR amendment, not a diff --
visible, and would stop rejected alternatives from being filed as items. If
they do not, the ADR annotation process already owns them. Cost: a
sentence either way. Risk: none visible.

## 8. The commissioned questions, answered in brief

- *How did processed items and follow-up items develop?* 140 items in 68
  days: 62 from decision and retrospective batches, 36 stated follow-ups of
  single items, 18 transcribed, the rest from reviews and free proposals. 89
  closed (72 executed, 17 retired). The open set rose from 25 to 47 in three
  weeks and has held at 50-56 since; creation fell month over month while
  closure stayed level. Two speeds: follow-ups execute in a median of two
  days, batch items wait and age. (Sections 2, 4.1)
- *Where is task aging observable?* In 17 fully obsoleted items (nine
  consolidations, two decision removals, two side-effect completions, three
  born stale, one filed alternative), in 75 accretive amendments on 47
  items, in five items that landed narrower than written, and in the
  dependency graph and cross-item claims themselves. Detection is same-day
  in the planning focus and 37-60 days in the tail. (Section 3)
- *Where is task explosion observable?* 19 executed items have child items;
  item-0114 produced eight touch points in one day; ADR-051 produced eleven
  items and then aged four; the deepest chain is five generations in six
  weeks. Explosion is bounded in count by absorption into existing items,
  which converts it into accretion. (Section 4)
- *Are there patterns?* Ten, in section 5: the order file runs as a stack;
  discovery precedes closure; decisions generate twice; items age fastest at
  birth and slowest in the tail; accretion instead of retirement; `done` is
  overloaded; decision items age by construction; claims about items age
  like items; the executor amends in passing; grooming comes in waves.
- *Do rules in the AI workflow contribute systematically?* Yes, on both
  sides. (Section 6)
- *Which?* Explosion: `AGENTS.md` "Code is liability" rule 4 and the
  mandatory "Follow-up candidates" section; `AI-WORKFLOW.md` anti-initiative
  ("the author turns those candidates into roadmap items"), authoring clauses
  2-4 (sibling closure, domain verification, deferral owners), the
  planning-state rule that turns retrospectives into items, decisions before
  instructions, and one concern per PR -- all by design, as the fix for
  mechanism M2. Aging: retire-rides-the-next-instruction, drift-invariance by
  exclusion, one-time ratification with a single exit, removal-as-default
  with append-only ADRs outside the store, no item ids in code, and the
  absence of any withdrawn state, amendment rule, re-validation trigger,
  staleness signal, link check, tail policy, or final-summary shape. The
  workflow built the channel from execution back to planning and not the
  one from planning back to execution.

## Appendix A: every item, with lifecycle and outcome

Dates are 2026; `amend` counts content amendments before completion (title,
goal, acceptance intent, or body). `outcome` is this reader's classification
from the final summary and the landing commits; `origin` is the stated source
(section 4.1), with the parent item where one is named.

| Item | Created | Ratified | Done | Amend | Outcome | Origin | Title |
|---|---|---|---|---|---|---|---|
| 0001 | 06-20 `6ba0c61` | 06-20 | 06-21 `4837075` | 0 | executed | transcribed | Wire the ADR-046 output model (one coherent instruction) |
| 0002 | 06-20 `6ba0c61` | 06-20 | - | 0 | open, ratified | transcribed | ADR-038 item 9: SSH-mediated per-connection observed records |
| 0003 | 06-20 `6ba0c61` | 06-20 | - | 0 | open, ratified | transcribed | ADR-038 item 8: rehost DoT resolver and TLS mediator onto ... |
| 0004 | 06-20 `6ba0c61` | 06-20 | - | 3 | open, ratified | transcribed | Observed-TLS identity consolidation (engine-cluster lead) |
| 0005 | 06-20 `6ba0c61` | 06-20 | - | 0 | open, ratified | transcribed | Engine hardening / transport-unification (flip hardenedByD... |
| 0006 | 06-20 `6ba0c61` | 06-20 | - | 0 | open, ratified | transcribed | ADR-040 2c: live end-to-end base-SBOM verification against... |
| 0007 | 06-20 `6ba0c61` | 06-20 | - | 1 | open, ratified | transcribed | ADR-040 instruction-5 arc: cosign independent verify-attes... |
| 0008 | 06-20 `6ba0c61` | 06-20 | - | 0 | open, ratified | transcribed | Harness H2: WebAuthn/FIDO2 identity hardening at the IdP |
| 0009 | 06-20 `6ba0c61` | 06-20 | 08-19 `845bade` | 0 | retroactive (landed 06-16) | transcribed | Harness H3-3b: add ctlogs entry to goldenTrustedRoot and r... |
| 0010 | 06-20 `6ba0c61` | 06-20 | 08-19 `737af88` | 0 | retroactive (landed 06-16) | transcribed | Harness H3-3c: flag-clean cosign conformance target |
| 0011 | 06-20 `6ba0c61` | 06-20 | 08-24 `9828bf0` | 0 | executed | transcribed | CT follow-on: strike verify enforces the embedded SCT (pos... |
| 0012 | 06-20 `6ba0c61` | 06-20 | 08-22 `c3209eb` | 0 | executed | transcribed | CT follow-on: pull ctlogs entry into liveTrustRoot (full c... |
| 0013 | 06-20 `6ba0c61` | 06-20 | - | 0 | open, ratified | transcribed | Full TLS single-port demux (parked: blocked on L3 source-I... |
| 0014 | 06-20 `6ba0c61` | 06-20 | 06-28 `256b7d0` | 0 | obsolete at birth (D1, 06-04) | transcribed | Upstream osv-scalibr decoupling PR (parked: organic ecosys... |
| 0015 | 06-20 `1d2babc` | 06-20 | 08-25 `105b3f4` | 0 | superseded (ADR-051 D5) | transcribed | Deploy-path SSH enablement (lift the deploy-path SSH rejec... |
| 0016 | 06-20 `1d2babc` | 06-20 | - | 4 | open, ratified | transcribed | Mandatory CUE lint step: machine-enforced layer direction ... |
| 0017 | 06-20 `3c173c6` | - | 06-28 `75d4773` | 0 | consolidated (0049) | transcribed | DoT resolver: combined IP + hostname declaration with SAN/... |
| 0018 | 06-20 `3c173c6` | - | 06-28 `75d4773` | 0 | consolidated (0049) | transcribed | DoT resolver: default to port 853 when omitted |
| 0019 | 06-20 `bb91468` | - | 06-28 `929e79b` | 0 | alternative recorded (ADR-047) | batch | Spec layering Option A: separate CUE+Go packages for a nat... |
| 0020 | 06-20 `ef1bc70` | 06-21 | 06-22 `412b86b` | 0 | executed | batch | Rename CUE package deploy to attest and delete the re-expo... |
| 0021 | 06-20 `ef1bc70` | 06-21 | 06-23 `4af56df` | 0 | executed | batch | Split lane.cue into base and wire prefix files; rename art... |
| 0022 | 06-20 `ef1bc70` | 06-21 | 06-23 `4359f23` | 0 | executed | batch | Move transport, provenance and trustroot specs to base and... |
| 0023 | 06-20 `ef1bc70` | 06-21 | 06-23 `53cf90d` | 0 | executed | batch | Split attest files, move meta specs to meta prefix, add ha... |
| 0024 | 06-20 `ef1bc70` | 06-21 | 06-24 `2a34714` | 0 | executed | batch | Consolidate duplicated value constraints into base-scalars |
| 0025 | 06-20 `ef1bc70` | 06-21 | 06-28 `9b6a876` | 0 | executed | batch | Update embed.go, Makefile, README and AGENTS.md for the ne... |
| 0026 | 06-21 `5af6743` | 06-21 | 06-21 `972ed4b` | 0 | executed | follow-up of 0001 | Enforce output id disjointness within a step |
| 0027 | 06-21 `5af6743` | 06-28 | - | 0 | open, ratified | follow-up of 0001 | Audit all tests with HTTP calls to assert response status |
| 0028 | 06-21 `fcd3bf3` | 06-21 | 06-21 `da02cc4` | 0 | executed | retro ADR-046 | Rename output-key symbols to match their semantics (ADR-04... |
| 0029 | 06-23 `b2c696d` | - | 06-28 `929e79b` | 0 | executed | follow-up of 0024 | Constrain trust-root rawBytes with base64 |
| 0030 | 06-23 `183b83d` | 06-28 | 06-30 `fa67cbb` | 0 | consolidated (0031, 0051-0057) | follow-up of 0024 | Consolidate meta-crossval sha256 and rework crossval test ... |
| 0031 | 06-23 `4e929f1` | 06-23 | 06-24 `9fe9261` | 0 | executed | proposal | Bundle CUE schema loading in an internal/cue foundation pa... |
| 0032 | 06-24 `243175c` | 06-24 | 06-25 `901cf14` | 0 | executed | proposal | Unify scalar value types CUE-first; split the digest wire ... |
| 0033 | 06-24 `3e9b818` | 06-24 | 06-25 `8418503` | 0 | superseded (0036) | proposal | Move the transport vocabulary to its own CUE package, mirr... |
| 0034 | 06-25 `73e9ace` | 06-25 | 06-30 `2051902` | 0 | executed | proposal | Make the internal Go API surface exhaustively type-clean |
| 0035 | 06-25 `4c63e45` | 06-25 | 07-11 `515539a` | 0 | executed | proposal | Drive cue codegen and fmt-check from go.mod, retiring the ... |
| 0036 | 06-25 `82fd7f4` | 06-25 | 06-26 `247ad10` | 1 | executed | proposal | Map the CUE structure semantically onto the Go package layers |
| 0037 | 06-26 `371640f` | 06-26 | 06-26 `41e43c9` | 1 | executed | batch | Rename the irreducible-vocabulary package spec to primitiv... |
| 0038 | 06-26 `371640f` | 06-26 | 06-28 `363e2b3` | 0 | superseded (0048) | batch | Add the concept tier and extract DeployTarget and provenan... |
| 0039 | 06-26 `371640f` | 06-26 | 06-28 `bf0ff06` | 1 | executed | batch | Collapse DigestRef and the wire Digest into a single diges... |
| 0040 | 06-27 `d9d2565` | 06-27 | 06-27 `b06a39f` | 1 | executed | batch | Consolidate the peer endpoints onto endpoint concept types |
| 0041 | 06-27 `d9d2565` | 06-27 | 06-28 `ae0eb41` | 2 | executed | batch | Merge the HTTPS service-client endpoint onto TLS and drop ... |
| 0042 | 06-27 `d9d2565` | 06-27 | 06-28 `9a00dde` | 1 | executed | batch | Merge the DoT resolver declaration onto the endpoint shape |
| 0043 | 06-27 `d9d2565` | 06-27 | 06-27 `dfc92c7` | 0 | side effect (0040) | batch | Remove the orphaned packed-authority host type after all e... |
| 0044 | 06-27 `5209e35` | 06-27 | 06-28 `3d77165` | 0 | executed | residue of 0037 | Clean up residual specs/ path references after the contrac... |
| 0045 | 06-27 `734bafd` | 06-27 | 07-11 `89f5320` | 0 | executed | follow-up (endpoint arc) | Add lintstutter regression gate for wire-noun-named accessors |
| 0046 | 06-28 `9a00dde` | 06-28 | 06-28 `df54a37` | 0 | executed | follow-up of 0042 | Make sealed.resolver mandatory and tie the observed record... |
| 0047 | 06-28 `f193e88` | - | 06-28 `75d4773` | 0 | consolidated (0049) | proposal | Declare the DoT resolver as a structured IP-plus-port endp... |
| 0048 | 06-28 `21538a2` | 06-28 | 06-28 `2184c4b` | 0 | executed | proposal | Consolidate the artifact-centric contract vocabulary into ... |
| 0049 | 06-28 `75d4773` | 06-28 | - | 0 | open, ratified | consolidation | Restructure resolver as separate host/ip/port with hostnam... |
| 0050 | 06-29 `af7e58b` | 06-30 | - | 4 | open, ratified | follow-up of 0034 | Make CUE the single source for every data-schema type; onl... |
| 0051 | 06-30 `768b60a` | 06-30 | 07-18 `407e326` | 0 | executed | batch | Reconcile the contract-packaging prose with the embedded-F... |
| 0052 | 06-30 `768b60a` | 06-30 | - | 3 | open, ratified | batch | Type the output handle image refs with the existing primit... |
| 0053 | 06-30 `768b60a` | 06-30 | 07-01 `406990f` | 0 | executed | batch | Remove the empty laneDigest disjunction from the sealed at... |
| 0054 | 06-30 `768b60a` | 06-30 | 07-02 `3db7843` | 0 | executed | batch | Type the observed-peer join keys and attribution values as... |
| 0055 | 06-30 `768b60a` | 06-30 | - | 1 | open, ratified | batch | Extend the trust-layer conformance test to the sealed proj... |
| 0056 | 06-30 `768b60a` | 06-30 | - | 2 | open, ratified | batch | Bind the crossval positive-case inputs to the real lane sc... |
| 0057 | 06-30 `768b60a` | 06-30 | 07-19 `56b257e` | 2 | executed, decision -> D10 | batch | Decide the deploy target naming, type, and namespace after... |
| 0058 | 06-30 `6866f34` | 06-30 | 07-02 `932406f` | 0 | executed | proposal | Enforce the migrate-to-CUE coverage rule with a mandatory ... |
| 0059 | 06-30 `6866f34` | 06-30 | 07-05 `f88091c` | 0 | side effect (0070) | follow-up of 0050 | Investigate whether the lane.State sync mutex belongs on t... |
| 0060 | 06-30 `31b5421` | 06-30 | 07-01 `9778e81` | 0 | executed | proposal | Canonicalize the attestation signing payload so signed byt... |
| 0061 | 06-30 `d25f424` | 07-01 | 07-01 `cac1a9c` | 0 | executed | proposal | Remove vestigial deploy-step host-disk emit (host-neutrality) |
| 0062 | 07-02 `c025225` | 07-11 | - | 0 | open, ratified | review | Cut the first release tag and keep the README bootstrap pi... |
| 0063 | 07-02 `fca4ac6` | 07-11 | - | 1 | open, ratified | review | Gate main behind a dogfooded strike lane with a coverage r... |
| 0064 | 07-02 `f97cae7` | 07-11 | - | 2 | open, ratified | review | Repair markdown cross-reference rot and gate relative doc ... |
| 0065 | 07-02 `e9a9ede` | 07-02 | 07-03 `57bb78a` | 0 | decomposed (0066-0068) | follow-up of 0058 | Resolve lane.DAG mixing exported data with unexported deri... |
| 0066 | 07-03 `10d5e55` | 07-03 | 07-04 `7981061` | 1 | executed | follow-up of 0065 | Move the step-id index to a Parse companion and add alloca... |
| 0067 | 07-03 `10d5e55` | 07-03 | 07-04 `39986c7` | 0 | executed | follow-up of 0065 | Extract a separate lane validation phase from the DAG reso... |
| 0068 | 07-03 `10d5e55` | 07-03 | 07-05 `3f195f8` | 0 | executed | follow-up of 0065 | Reduce the DAG to adjacency and order, merge the walks, de... |
| 0069 | 07-03 `1d186eb` | 07-03 | 07-05 `5f7e488` | 1 | executed | follow-up of 0066 | Add a runState-side image-from resolver for runtime-resolv... |
| 0070 | 07-04 `d3ff624` | 07-04 | 07-06 `8e27d97` | 0 | executed | follow-up of 0069 | Consolidate lane-run status into one write-once per-step s... |
| 0071 | 07-07 `e1ff84d` | 07-08 | 07-09 `5945d91` | 1 | executed | batch | Restructure workflow docs and land the ratified authoring ... |
| 0072 | 07-07 `e1ff84d` | 07-08 | 07-10 `4c51030` | 1 | executed | batch | Adjudicate the dual-audit disputed set and codify the cate... |
| 0073 | 07-07 `e1ff84d` | 07-08 | 07-11 `dd8fe3c` | 0 | executed | batch | Stand up tools/linttypeflow from the audit extractor bluep... |
| 0074 | 07-07 `e1ff84d` | 07-08 | 07-11 `d2be51e` | 2 | executed | batch | Contract-authoring checks: primitive reuse, lossy map-key ... |
| 0075 | 07-07 `e1ff84d` | 07-08 | 07-12 `3a75009` | 0 | executed | batch | Type the trust-anchor and fingerprint fields across the co... |
| 0076 | 07-07 `e1ff84d` | 07-08 | 07-15 `33b4c16` | 2 | executed, 3 of 6 clauses | batch | lane contract typing cluster: keys, references, defaults |
| 0077 | 07-07 `e1ff84d` | 07-08 | 07-18 `0316156` | 1 | executed | batch | Type provenance timestamps and route the target reference ... |
| 0078 | 07-07 `e1ff84d` | 07-08 | - | 1 | open, ratified | batch | Give the local image reference one owner |
| 0079 | 07-07 `e1ff84d` | 07-08 | - | 4 | open, ratified | batch | Type the path threading below the contract |
| 0080 | 07-07 `e1ff84d` | 07-08 | - | 2 | open, ratified | batch | Typed capsule identity, canonical host, and the twin collapse |
| 0081 | 07-07 `e1ff84d` | 07-08 | - | 3 | open, ratified | batch | Type the verify and keyless chains |
| 0082 | 07-07 `e1ff84d` | 07-08 | - | 2 | open, ratified | batch | Ingest parse discipline and scalar vocabulary hygiene |
| 0083 | 07-07 `e1ff84d` | 07-08 | - | 1 | open, ratified | batch | Eliminate in-band grammar sentinels |
| 0084 | 07-07 `e1ff84d` | 07-08 | - | 2 | open, ratified | batch | Escalate linttypeflow to the judgment-adjacent check classes |
| 0085 | 07-09 `335ac42` | 07-09 | - | 0 | open, ratified | fork C | Type the OIDC and signer identity on the repaired canonica... |
| 0086 | 07-09 `ce859ca` | 07-10 | 08-22 `23d3e2e` | 1 | executed | batch | Consolidate the engine-address parse and admit only unix a... |
| 0087 | 07-09 `ce859ca` | 07-10 | 08-22 `ea4982f` | 0 | executed | batch | Move the known_hosts host projection into the endpoint pac... |
| 0088 | 07-09 `ce859ca` | 07-10 | 08-22 `ce77d2c` | 0 | executed, different type than title | batch | Type transport.DialTCP on endpoint.Address |
| 0089 | 07-09 `ce859ca` | 07-10 | - | 1 | open, ratified | batch | Enforce structured logging with log/slog and retire the sa... |
| 0090 | 07-09 `ce859ca` | 07-10 | 07-12 `42acf91` | 0 | executed | batch | Hoist inline string disjunctions in the contract into name... |
| 0091 | 07-09 `ce859ca` | 07-10 | 07-13 `3d5310d` | 0 | executed, mostly pre-decided | batch | Decide the visibility of generated enum constants |
| 0092 | 07-09 `ce859ca` | 07-10 | - | 0 | open, ratified | batch | Collapse the hand-written ConnectionInfo mirror of the eng... |
| 0093 | 07-11 `42b0d33` | 07-11 | - | 2 | open, ratified | follow-up of 0073 | Consolidate the Go-type linters into gotypelint and adopt ... |
| 0094 | 07-11 `d2be51e` | 07-11 | - | 1 | open, ratified | follow-up of 0093 | Make the standalone cuelint gate go-native so its Makefile... |
| 0095 | 07-11 `d2be51e` | 07-11 | 08-22 `a09cc12` | 0 | executed | batch | Replace the shell-based lint gates with go-native checks |
| 0096 | 07-11 `d2be51e` | 07-11 | - | 0 | open, ratified | batch | Retire the root Makefile: rehome the thin wrappers and mig... |
| 0097 | 07-11 `d2be51e` | 07-11 | - | 0 | open, ratified | batch | Retire the sigstore-local test Makefile so no Makefile rem... |
| 0098 | 07-11 `2c166e9` | 07-12 | - | 0 | open, ratified | follow-up of 0075 | Type resolver record host and fingerprint; model resolver-... |
| 0099 | 07-12 `0fb9171` | 07-12 | 07-13 `8be1b30` | 0 | executed | proposal | Apply the named-discriminator pattern to the trust, deploy... |
| 0100 | 07-15 `33b4c16` | - | 07-18 `8c98677` | 0 | moot (ADR-051 D9, 0107) | follow-up of 0076 | Type the deploy artifacts map key and retire the wrap-unwr... |
| 0101 | 07-18 `f5d7afb` | 07-18 | - | 0 | open, ratified | batch | Widen #Authority to accept bracketed IPv6 literals |
| 0102 | 07-18 `18161ea` | 07-18 | 07-19 `97b4138` | 0 | executed | batch | Remove PackSpec.configFiles and FileEntry |
| 0103 | 07-18 `18161ea` | 07-18 | 07-19 `eddad8a` | 0 | executed | batch | Remove dead schema: DeploySpec.source.gitImage and PackSpe... |
| 0104 | 07-18 `18161ea` | 07-18 | 07-19 `7ff36b0` | 0 | executed | batch | Relocate the provenance declaration and single-home Source... |
| 0105 | 07-18 `18161ea` | 07-18 | 07-19 `c863c68` | 0 | executed | batch | Remove the custom deploy method |
| 0106 | 07-18 `18161ea` | 07-18 | 07-19 `881d138` | 0 | executed | batch | Apply the ratified item-0057 deploy target naming, type, a... |
| 0107 | 07-18 `18161ea` | 07-18 | 08-09 `695ce6d` | 1 | executed, leaner than title | batch | Restructure deploy artifacts into one pushed image plus SB... |
| 0108 | 07-18 `18161ea` | 07-18 | 08-12 `5e60c78` | 1 | executed | batch | Registry deploy sealing point: structured target, control-... |
| 0109 | 07-18 `18161ea` | 07-18 | 08-12 `5e60c78` | 1 | absorbed (0108) | batch | Structure the registry push target: endpoint plus OCI name |
| 0110 | 07-18 `18161ea` | 07-18 | 08-12 `5e60c78` | 1 | absorbed (0108) | batch | Push the deploy image from the control plane, remove the e... |
| 0111 | 07-18 `18161ea` | 07-18 | - | 1 | open, ratified | batch | Source kubernetes manifests from artifacts, not strike stdin |
| 0112 | 07-18 `18161ea` | 07-18 | - | 1 | open, ratified | batch | Reconcile the ADR-016 pairing identity after the deploy ta... |
| 0113 | 07-18 `10d0d22` | 08-12 | 08-12 `0c54298` | 0 | executed | batch | Remove the deploy target identity (#Deploy) and #DeploySpe... |
| 0114 | 08-10 `78ea223` | 08-12 | 08-16 `0b44659` | 1 | executed | follow-up of 0107 | SBOM-decompose deploy artifacts into a name-keyed map of i... |
| 0115 | 08-11 `28f3483` | 08-12 | 08-12 `0c54298` | 0 | executed | follow-up of 0108 | Consolidate OCI 1.1 referrer semantics into registry.Artif... |
| 0116 | 08-11 `28f3483` | 08-12 | 08-15 `549b83c` | 1 | executed | follow-up of 0108 | Live registry-deploy integration test against a harness OC... |
| 0117 | 08-11 `28f3483` | 08-12 | 08-12 `7ef466a` | 0 | executed | follow-up of 0108 | AI-WORKFLOW.md: instruction contract gains a deviations-pa... |
| 0118 | 08-12 `82050ef` | 08-15 | 08-22 `ec38e88` | 0 | executed | follow-up of 0113 | Drop the removed target package from the contract-layering... |
| 0119 | 08-14 `993db12` | 08-15 | 08-23 `ecf3066` | 0 | executed | follow-up of 0116 | Fail-fast gate for the Cloudflare fingerprint integration ... |
| 0120 | 08-14 `993db12` | 08-15 | 08-19 `418aa5e` | 4 | executed | follow-up of 0116 | Reclassify the keyless golden generator out of the default... |
| 0121 | 08-15 `41c44c4` | 08-23 | - | 0 | open, ratified | follow-up of 0120 | Isolate container-heavy test packages from shared-engine s... |
| 0122 | 08-15 `f6c0ace` | 08-15 | 08-16 `0d9cd81` | 1 | executed | follow-up named in ADR-035 | Eliminate the remaining host-filesystem payload round-trips |
| 0123 | 08-15 `bd5712c` | 08-15 | 08-16 `970fe7e` | 0 | executed | audit 41c44c4 | Seal the pushed digest and verify the engine export (ADR-0... |
| 0124 | 08-16 `f4521c7` | 08-23 | - | 0 | open, ratified | follow-up of 0114 | Anchor cache-restored file-output handles in a control-pla... |
| 0125 | 08-16 `0d9cd81` | 08-23 | - | 0 | open, ratified | follow-up of 0122 | Shrink the test-side host-filesystem exemption to one decl... |
| 0126 | 08-16 `e7c5939` | 08-23 | - | 0 | open, ratified | follow-up of 0122 | Sharpen ADR-034 so its containment domain is the element, ... |
| 0127 | 08-16 `e7dd200` | 08-23 | - | 0 | open, ratified | follow-up of 0114 | Live region-SBOM coverage: a run step with a file output i... |
| 0128 | 08-16 `e7dd200` | 08-23 | - | 0 | open, ratified | follow-up of 0114 | Decide whether per-artifact SBOM digests project into the ... |
| 0129 | 08-18 `cc82e7c` | 08-18 | 08-18 `872a432` | 0 | executed | not stated | Rename the role-neutral wire package and single-source the... |
| 0130 | 08-19 `0a8a923` | 08-23 | - | 0 | open, ratified | not stated | One construction for outbound HTTPS to a declared peer |
| 0131 | 08-19 `0a8a923` | 08-23 | - | 0 | open, ratified | follow-up of 0120 | Refresh the golden lane fixture header and regenerate the ... |
| 0132 | 08-20 `548eaaf` | 08-20 | 08-21 `6c7d3e4` | 0 | executed | incident | Recover the local sigstore harness automatically when the ... |
| 0133 | 08-20 `548eaaf` | 08-20 | - | 1 | open, ratified | follow-up of 0097 | Move the sigstore harness key material and anchor export o... |
| 0134 | 08-20 `548eaaf` | 08-20 | - | 1 | open, ratified | follow-up of 0133 | Drive the sigstore harness from a declared CUE topology ov... |
| 0135 | 08-22 `6e15154` | 08-23 | - | 0 | open, ratified | follow-up of 0119 | Remove the privileged-port bind skips from the mediator an... |
| 0136 | 08-23 `f3918aa` | 08-23 | 08-23 `a95de9c` | 1 | executed | follow-up of 0119 | Make mediator cancellation real and never leave a step con... |
| 0137 | 08-23 `6fba150` | - | - | 0 | open, proposed | follow-up of 0136 | Publish first-wins identity captures by compare-and-swap a... |
| 0138 | 08-23 `6fba150` | - | - | 0 | open, proposed | follow-up of 0136 | Give capture records a single owner and make Records final... |
| 0139 | 08-23 `6fba150` | - | - | 0 | open, proposed | follow-up of 0136 | Close the certificate universe at CA construction |
| 0140 | 08-23 `6fba150` | - | - | 0 | open, proposed | follow-up of 0136 | Bind SSH bridges to a capsule-owned context, delete the cl... |

## Appendix B: reproduction

Every table above derives from the per-item timeline produced by the script
below, run against a full clone at `e18d8a4`. It walks each commit that
touched `roadmap/`, parses every version of every item file, and writes one
JSON record per version. The second stage -- executed-versus-retired,
origin, amendment types -- is a reading of final summaries, item bodies, and
commit bodies, recorded in appendix A and sections 3 and 4 so it can be
redone.

```python
#!/usr/bin/env python3
"""Walk every commit touching roadmap/ and record, per item, every version
of the item file: commit, date, path, frontmatter fields, body hash."""
import hashlib, json, re, subprocess
from collections import defaultdict

REPO = "."  # path to the clone

def git(*args):
    return subprocess.run(["git", "-C", REPO, *args], capture_output=True,
                          text=True, check=True).stdout

def parse_frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n?(.*)$", text, re.S)
    if not m:
        return {}, text
    fm = {}
    for line in m.group(1).split("\n"):
        mm = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if mm:
            fm[mm.group(1)] = mm.group(2).strip()
    return fm, m.group(2)

def parse_list(v):
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [x.strip().strip('"') for x in inner.split(",")] if inner else []
    return [v.strip('"')] if v else []

commits = git("log", "--reverse", "--format=%H|%h|%ad|%s", "--date=short",
              "--", "roadmap/").strip().split("\n")
timeline = defaultdict(list)
for line in commits:
    full, short, date, subject = line.split("|", 3)
    for ch in git("show", "--name-status", "--format=", full).strip().split("\n"):
        if not ch.strip():
            continue
        parts = ch.split("\t")
        kind, path = parts[0][0], parts[-1]
        m = re.search(r"(item-\d{4})\.md$", path)
        if not path.startswith("roadmap/") or not m:
            continue
        iid = m.group(1)
        if kind == "D":
            timeline[iid].append({"sha": short, "date": date, "kind": "D", "path": path})
            continue
        fm, body = parse_frontmatter(git("show", f"{full}:{path}"))
        fs = re.search(r"## Final summary\s*\n(.*)$", body, re.S)
        timeline[iid].append({
            "sha": short, "date": date, "subject": subject, "path": path, "kind": kind,
            "status": fm.get("status", ""), "title": fm.get("title", "").strip('"'),
            "arcs": parse_list(fm.get("arcs", "[]")), "rank": fm.get("rank", "").strip('"'),
            "depends_on": parse_list(fm.get("depends_on", "[]")),
            "links": parse_list(fm.get("links", "[]")),
            "goal_hash": hashlib.sha1(fm.get("goal", "").encode()).hexdigest()[:8],
            "acceptance_hash": hashlib.sha1(fm.get("acceptance_intent", "").encode()).hexdigest()[:8],
            "acceptance_len": len(fm.get("acceptance_intent", "")),
            "body_hash": hashlib.sha1(body.encode()).hexdigest()[:8], "body_len": len(body),
            "final_summary": fs.group(1).strip() if fs else "",
        })
json.dump(dict(timeline), open("timeline.json", "w"), indent=1)
```

Derived quantities, for the reader who reruns it: an item's creation is its
first version; ratification is the first version with `status: ratified`;
completion is the first version with `status: done` (the same commit that
moves the file to `completed/`); a content amendment is any version before
completion whose title, goal hash, acceptance hash, or body hash differs from
the previous version. Origin and outcome are read, not computed.
