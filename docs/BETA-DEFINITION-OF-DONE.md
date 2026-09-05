# strike -- Beta Definition of Done

**Project:** `github.com/istr/strike`
**Status:** ratified by the operator (F1), 2026-07-02
**Anchor at ratification:** `3db7843082df908d9ac2b06048ea840bb60dd383`
**Custodian:** operator; amendments ride an explicit ratification, never a silent edit.
**Companion:** `strike-swot-analysis-3db7843.md` (evidence base and rationale).

---

## The bar

strike ships as beta when every externally documented base promise -- README, SECURITY.md, ARCHITECTURE.md, DESIGN-PRINCIPLES.md -- is in exactly one of two states: **(a) green behind a machine-checkable gate**, or **(b) explicitly declared as a limitation in the shipped documentation**. Nothing may sit between the two. This is the project principle "enforcement is structural, not discretionary" applied to the release itself: the beta is done when the gates say so, not when it feels done.

A promise counts as gated only if an outsider could re-run the check: a lint or conformance target in `make check`, a hosted gate, a documented offline verification against a published artifact, or the self-bootstrap compare. Operator memory and chat history do not count as gates.

## Gate matrix

Status legend: **green** (gate exists and passes at the anchor), **red** (work open), **pending** (gate defined, dynamic validation outstanding), **deferred** (ratified out of the beta, ships as documented limitation).

| # | Promise | Machine-checkable gate | Items | Status |
| --- | --- | --- | --- | --- |
| 1 | No shell, no exec, no root, secrets typed, external refs digest-pinned | Existing lint/schema gates in `make check`; grep-verifiable invariants | -- | green |
| 2 | Producer attestation chain: DSSE + Fulcio keyless + Rekor v2 + RFC3161 + SBOM referrers, canonicalized payload | Existing hermetic suite + golden bundles | -- | green |
| 3 | CUE first -- schema drift structurally impossible; only disjunction glue stays hand-written | item-0058 linter mandatory in `make check` and green; migrations landed | 0058, 0050, 0052, 0059 (finding) | red |
| 4 | Sealed projection cannot drift from the SLSA external-parameters projection | Trust-layer conformance test extended to the sealed section and green; crossval positives typed against the real schemas | 0055, 0056 | red |
| 5 | Attest wire stable for the beta line | Freeze declaration below, effective when item-0057 lands | 0057 | pending |
| 6 | Offline verifiability, independently provable: "check the record without trusting strike or the engine" | cosign verify-attestation passes offline and flag-clean against published bundles; CT/SCT posture symmetric in `strike verify`; live e2e base-SBOM path green against the harness | 0006, 0007, 0009, 0010, 0011, 0012 (+ harness item-0008) | red |
| 7 | End-to-end soundness branch is real when engine shares the trust domain | Declared engine identity in the lane schema; `hardenedByDeclaration` true; observed-vs-declared match with negative test | 0004, 0005 | red |
| 8 | Observed-peer coverage symmetric across peer types | SSH mediator emits per-connection observed records alongside TLS and DoT | 0002 | red |
| 9 | Wire-vs-internal layer direction machine-enforced | CUE layer-direction lint failing the hosted gate | 0016 (substrate: 0063) | red |
| 10 | No local toolchain -- "you only need a running rootless podman" | README bootstrap succeeds on a host with only rootless podman; no cue binary in the Containerfile; Containerfile builds the tree it pins | 0035, 0062 | red |
| 11 | Reproducibility proven by the self-bootstrap compare step | Bootstrap lane compare green at the release pin | 0062 (validation) | pending |
| 12 | Quality gates binding beyond one machine; coverage cannot silently decrease | Hosted verbatim `make check` gates main; coverage ratchet with recorded floor (61.9 percent raw at the anchor) | 0063 | red |
| 13 | Documentation internally consistent and reference-clean | Relative-link lint gate green; README structure current; embed claims reconciled | 0064, 0051 | red |
| 14 | Deferred capabilities are honest | One-sentence limitation for each deferral present in shipped docs | see Deferrals | deferred |

Path-neutral riders that carry no external promise -- 0027 (HTTP status assertions), 0045 (lintstutter), 0049 (resolver restructure) -- are not beta gates and slot on executor capacity.

## Attest wire freeze (ratified F2, 2026-07-02)

Effective the moment item-0057 lands: **`contract/attest` is frozen for the beta line.** Any subsequent change to the attest wire shape -- fields, types, constraints, disjunctions, serialization-visible structure -- is a beta-blocking event that requires explicit operator ratification and a re-baselining of every conformance golden built on it. Checks that merely observe the wire (items 0055, 0056, the conformance cluster) run after the freeze by design: if one of them surfaces pressure to change the wire, that pressure goes through the ratification gate, never around it. Formalization as a D-list entry or ADR is available at the operator's discretion; this document records the ratification.

## Sequencing

`_order.md` in the tree remains the single cross-arc execution truth; this section records the ratified shape it converges to, not a competing list.

1. **Schema-affecting first:** 0058 (linter, red-to-green driver) -> 0050 -> 0051 -> 0052 -> 0057. The freeze becomes effective with 0057.
2. **Checks against the frozen wire:** 0055, 0056.
3. **Toolchain and bootstrap promise:** 0035, then 0062 (tag only after the Containerfile builds the pinned tree -- the 0035-first vs minimal-fix fork is recorded in item-0062).
4. **Infrastructure:** 0063 before or with 0016 (0016 presupposes a CI to fail); 0064 as a docs-only PR at any convenient point, bundling the deferral limitation notes if the operator so chooses.
5. **Soundness flip:** 0004 -> 0005; then 0002.
6. **Independent-verifier cluster last, against the frozen wire:** 0006 -> 0007 -> 0008 -> 0009 -> 0010 -> 0011 -> 0012.
7. Riders 0027, 0045, 0049 wherever executor capacity allows.

The beta tag is cut when rows 1-13 are green/pending-validated and row 14's limitation notes are in the shipped docs.

## Deferrals (ratified F3, 2026-07-02)

- **item-0003** (DNS centralization onto the front) -- behind beta.
- **item-0015** (deploy-path SSH enablement) -- behind beta.

Each deferral is satisfied for the beta only when the shipped documentation states the limitation in one sentence (deploy steps reject SSH peers; DNS/DoT mediation is per-step, not front-centralized). The notes may ride item-0064's documentation PR or their own; they must exist before the beta tag.

**Not deferred:** item-0035 is beta-critical (ratified F3) -- it is the prerequisite of the no-local-toolchain bootstrap promise, one of the oldest documented and still unfulfilled: the USP is that a user needs nothing but a running rootless podman.

## Explicitly out of scope for the beta

item-0013 (parked: single-port TLS demux), the Rust second implementation against the crossval vectors, deployment-receipt predicate standardization, workflow publication, and any coverage arc beyond the ratchet (the pre-vs-post-beta decision on a signed-core coverage arc is an open operator fork, analysis section 7).

## Risk watchlist during the beta run-up

- `rekor-tiles` is pinned to a pseudo-version; lift to a release when one exists and re-run the conformance goldens.
- Re-baseline the model-behavior retrospective at the next model generation change.
- External SLSA wording stays "design mapping" until row 6 is green.
- Any post-freeze pressure on `contract/attest` is handled as a beta-blocking ratification event.

## Open ratification points (non-blocking for the current order)

1. item-0063 CI variant: (A) minimal GitHub Actions without third-party actions vs (B) dogfooded strike lane with the forge as status reporter.
2. Freeze formalization vehicle (D-list entry or ADR) beyond this document.
3. Coverage target statement in DEVELOPMENT.md: keep 100 percent wording plus a signed-core coverage arc, or re-scope.
4. item-0064 optional rider: non-systemd podman-socket note in the README prerequisites.
