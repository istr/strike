# Attestation soundness and the trust boundary

## Thesis

End-to-end software attestation is sound only under trust in the **entire build
environment** -- control plane *and* engine. With trust in the control plane
alone, attestation is **best effort**: sound exactly on the claims the control
plane seals by its own action, and silent-but-marked elsewhere. The system
tolerates an adversarial **subject** of attestation (a malicious source, a
malicious step container) but not an adversarial **substrate** (an engine that
breaks complete ingress/egress mediation or misreports to the control plane).
This is not an implementation gap; it is a structural necessity, argued below,
with no escape short of making the engine trusted -- by assumption (co-located,
host-trusted) or by a hardware root of trust (TEE).

## Model

- **CP** -- control plane / strike controller. The attester: holds the signing
  key the engine never sees (ADR-007), emits the signed predicate. CP is
  **non-executing** -- no subprocess, no shell (ADR-001/022). Every interaction
  with the build environment goes through the engine API or through
  filesystem/network endpoints the engine populates or routes.
- **E** -- engine. Creates and runs containers, materializes their mounts, sets
  up and confines their network. Trust status is the variable under study.
- **C** -- step containers. Adversarial by assumption (threat model: untrusted).
- **V** -- verifier. External consumer of the predicate; brings its own trust
  assumptions; shares with CP only the cryptographic foundations (authenticity
  of the signing key, soundness of hash/signature).

**Soundness.** A claim phi that CP attests is *sound against adversary A* if A
cannot cause CP to attest phi while phi is false -- no false positives. *End-to-end
attestation* means every link from signed source to deployment outcome is sound.
*Best effort* means some links are not, and the predicate says so.

**The mediation function.** CP never observes the world W directly; it observes
`O = f_E(W)`, where `f_E` is E's behavior on CP's API calls and materializations.
Honest E => `f_E` faithful. Malicious E => `f_E` adversary-chosen, constrained only
by what CP can verify *without reference to E*.

## What CP can verify without E

Exactly two things:

1. **Data CP holds independently of E** -- its signing key; trust anchors it
   carries (a peer's pinned cert, the Rekor public key); the lane file, which CP
   reads and hashes itself.
2. **Values bound to a CP-controlled cryptographic seal that the consumer
   dereferences by content-address and verifies independently** -- concretely,
   a digest D that CP signs and the consumer resolves by D, checking
   `hash(received) = D`. The binding runs through D at *both* ends; a
   substituted byte produces a hash mismatch the consumer detects, never a
   false positive. What is required is the **consumer protocol** (dereference
   by the signed digest, verify), not where the bytes physically live: E's
   residual power against this construction is **denial, not deception**. So
   E's position relative to the store is irrelevant to soundness; what matters
   is that the consumer's resolution path runs through D.

Everything else CP "knows" is `f_E(W)` -- true iff E chose to be faithful.

## Mediation theorem (informal)

> For a non-executing CP, any claim phi about the build environment whose truth is
> fixed neither by (1) nor by (2) above is not sound against a malicious E.

Three corollaries fix the exact boundary -- and reproduce, from first principles,
the V / E / informational split derived empirically in the layer classification.

**C1 -- Completeness is never sound against malicious E.** "Egress was confined to
declared peers"; "these were all the inputs." A completeness guarantee needs a
non-bypassable reference monitor (Anderson: tamper-proof, always-invoked,
verifiable). Non-bypassability of the container's I/O is enforced by E (netns,
egress lock, opaque relay). A malicious E grants a side channel CP cannot see --
by definition a bypassed path does not reach CP's front. The failure is a
**silent false negative**: the predicate claims a confinement that did not hold.
-> **Layer E.**

**C2 -- Intra-run content identity is not sound against malicious E.** A value CP
hashes mid-run (a step-to-step handoff, a state capture) is exposed to
**equivocation**: E serves bytes B1 to CP's verification read and materializes B2
to the actual consumer. CP's hash is true of B1, false of what was used; no
CP-controlled seal spans the gap. -> **Layer E.**

**C3 -- Published-artifact identity *is* sound against malicious E.** The unique
content claim that survives: CP signs the digest D; the consumer dereferences
by D and verifies `hash(received) = D`. The binding runs through D at *both*
ends -- not through any store, not through E's position. E may corrupt or
withhold bytes; any substitution produces a hash mismatch the consumer detects
(denial, never deception). -> **Layer V.** The container's malice is
*contained* here, not attested away: if C produced malicious B2 but CP
read/sealed/published honest B1, any retrieval by D returns B1 or fails
verification, and "published artifact = Y" stays true.

*Pre-empting an objection.* It is tempting to ask whether the same construction
rescues C2 by "moving the read-write surface into CP." It does not, for a
structural reason: C3 works because **both ends dereference by the same signed
digest** -- CP needs no presence on the I/O path. C2's intra-run consumer is the
next step container, which retrieves bytes through mounts E materializes, not
through a digest it itself resolves. Rescuing C2 the C3 way would require CP
on the I/O path -- i.e. CP materializing mounts and routing writes, which is
kernel-mediated execution. A CP that does this *is* an engine (Escape 1
below): the CP/E distinction is precisely the line between a non-executing
sealer and the entity that materializes I/O. Nominal "ownership" of a
directory does not help while E remains the bind-mounter and router; the path
becomes CP-owned only when CP performs the materialization itself, at which
point trust is relocated, not removed.

## Why the line falls between subject and substrate

A malicious **container** is a malicious *subject*. It sits **downstream of every
seal**: its output is either sealed by CP (C3 -- contained) or flows onward as an
E claim (C1/C2 -- marked). It can produce garbage, but it cannot make CP attest a
false V claim, because V claims are about *CP's own sealing actions*, not about
C's behavior. A malicious subject yields a soundly-attested "this is what came
out," not a false attestation. Hence the threat model tolerates it.

A malicious **engine** is a corrupted *substrate*. It supplies no bad input; it
corrupts the *measurement apparatus* -- it **is** `f_E`. It decides what CP
observes (C1, C2), enforces or forgoes the monitor's non-bypassability (C1), and
materializes every handoff (C2). The distinction is a **lying witness** (the
container -- cross-examined and contained by the seals) versus a **forging court
reporter** (the engine -- nothing in the transcript is reliable).

> Attestation tolerates adversarial subjects and requires a trusted substrate.

That is exactly "malicious containers yes, malicious engine no." Note what a
malicious E does *not* do: it does not corrupt CP. CP stays honest; the key stays
secret. E corrupts CP's *observations*. That is precisely why V-claims
(independent of `f_E`) survive a malicious E and E-claims (functions of `f_E`) do
not -- the same fact, stated as soundness.

## No escape (necessity)

End-to-end soundness against a malicious E is impossible for a non-executing CP.
The candidate escapes, and where each actually goes:

1. **CP observes everything itself.** Impossible by construction: CP does not
   execute. To observe directly it would run tooling on the host (forbidden by
   No-exec; and the host is itself part of the build environment whose trust is
   in question) or in a container (back through E). A CP that executes and
   observes directly *is* an engine -- the CP/E distinction collapses and "trust
   the build environment" becomes "trust that merged executor." Trust relocated,
   not removed.
2. **The engine proves its own honesty in software.** It cannot: any proof it
   emits, a malicious instance emits while lying, since it controls its own
   execution. The only working root is a **TEE** measuring and mediating E. But a
   TEE *moves* trust to the hardware vendor + measured TCB and -- decisively --
   certifies *what code runs*, not *that mediation was complete*, unless the TEE
   also mediates all I/O, i.e. the TEE *becomes* the trusted monitor. TEE is not
   an escape from the thesis; it is how engine-trust is **earned** rather than
   **assumed**. Still the trusted-engine branch.
3. **Reproducible builds + independent rebuild.** This dilutes trust across
   replicas (independent builders would have to collude or all be compromised)
   and lets V *re-derive* the artifact. It strengthens the *value* of the V-zone
   but converts no E-dependent link into an E-independent one: it lowers the
   probability of undetected single-build compromise, never to zero, and cannot
   rebuild a *deployment* or a *runtime state*. Bounded to artifacts,
   probabilistic -- not soundness.
4. **Commitment schemes, transparency logs, accountable VMs.** Worth naming
   explicitly because they are a natural cryptographer's reflex. None
   introduces a new escape. Any commitment E emits is over data E controls --
   committing to B1 and serving B2 is equivocation, and catching it requires
   an independent observer *at the consumer*, which is either C3's seal
   mechanism (already counted) or a trusted substrate. Transparency logs
   (Rekor included) create a tamper-evident record of what was submitted; a
   malicious E logs a false observation as faithfully as a true one, and the
   log preserves the falsehood. Logs strengthen the V-zone (non-repudiable
   timestamps, signed entries) without converting any E-link into a V-link.
   Accountable-VM constructions either reduce to a TEE (escape 2) or to
   external observation (escape 1).

No remaining path yields single-build soundness on the E-dependent links without
trusting E. Hence:

> **End-to-end attestation <=> trusted build environment (CP U E).**

CP-trust is the irreducible floor: an untrusted CP's key-holder signs anything,
so there is no attestation at all. *Every* attestation presupposes trust(CP);
*end-to-end* attestation additionally requires trust(E). Best effort is exactly
**trust(CP) /\ ~trust(E)**.

The biconditional inherits one architectural premise: a **non-executing CP**
(ADR-001/022 plus the No-exec principle). Any candidate escape that relaxes it
collapses CP into E (Escape 1) -- trust relocated, not removed. The
biconditional therefore holds *wherever the CP/E distinction exists*, which is
the only setting in which "best effort" is a meaningful position to occupy.

## The two conditions, answered

**Best effort -- ~trust(E).** Sound on the V-zone only: declared lane scalars,
published artifact digest/signature/SBOM, front-observed peer identity,
Rekor-anchored timestamps. Every E-dependent link (build provenance, egress
completeness, runtime state, intra-run handoffs) is present but **marked** E --
present for a verifier who supplies engine-trust, sound for no one who does not.

**End-to-end -- trust(E).** The E-zone becomes sound too; the chain closes from
signed source to deployment outcome. Engine-trust is satisfied either by
**assumption** (engine co-located in CP's trust domain) or **earned** (TEE
attestation of the engine TCB). One subtlety on the sufficiency side: an honest
engine still requires an **expressive enough API** -- an engine that *cannot
report* complete egress (because the surface is not in the API) leaves the
corresponding claim unsound by blindness, not malice. API coverage gaps are a
separable, honest failure mode; trust(E) alone is necessary but not sufficient
without it.

**Operational mapping (the topology this lands on).** When the engine is **local
rootless** -- same principal/host as CP, and SECURITY.md already places "the host
running strike" in the trusted set -- ~trust(E) implies ~trust(CP): they share a
trust domain, so a compromised engine *is* a compromised host *is* a compromised
attester, and "honest CP, malicious E" is incoherent. Local therefore **is** the
end-to-end branch whenever attestation exists at all. (This collapse rests on
the current configuration -- same UID, signing key in CP process memory. An
intra-host isolation that walls CP's key off from E -- TEE, HSM, isolated process
under a stricter access regime -- would restore CP/E distinguishability locally
and is exactly the "earned engine-trust" path of Escape 2, applied inside the
host.) The best-effort branch is *only meaningful* when E is a **distinct trust
domain** -- the **remote engine over TCP** (`CONTAINER_TLS`). So:

> **remote engine => best effort** (unless that remote engine is independently
> trusted or TEE-attested); **local / co-trusted engine => end-to-end.**

The trust-layer split is the machine-readable boundary between these two
deployments. It also maps to *who verifies*: V-zone -> sound to **any** verifier;
E-zone -> sound only to a verifier who **trusts the engine**; informational ->
meaningful only under trust the verifier **brings independently**.

## What this commits us to

1. **The aim sentence must be qualified.** "End-to-end software attestation and
   provenance tracing" is sound *under a trusted engine*; under an untrusted
   (remote) engine it is *best-effort, scope-marked*. The README/docs claim
   should carry that conditional, not assert end-to-end unconditionally -- a
   truth-in-advertising obligation for a tool whose entire value is soundness.
2. **The predicate must be self-describing about scope.** A verifier must read,
   from structure alone, which links are V (rely freely), E (rely iff you trust
   the engine), informational (rely only under your own assumptions). The
   three-section split *is* that self-description; it is what makes "best effort"
   honest rather than misleading.
3. **No code change claims an E-link is a V-link.** Any implementation recording
   an E-dependent value in a V position is unsound -- the stage-2 bug class to
   hunt.

## Open placement (operator's call)

Foundational and currently homeless:

- **(a)** Fold as the rationale of ADR-037 -- it *is* the theory under D2/D4. But
  ADR-037 is frozen accepted input; this would be an explicit amendment.
- **(b)** A new `docs/` foundation note, cited by ADR-037 and SECURITY.md.
- **(c)** A short operator-facing SECURITY.md "Trust model: best-effort vs
  end-to-end" subsection, backed by this long-form note.

Recommendation: **(b) plus a short (c) pointer** -- keep ADR-037 frozen, give the
theory its own citable home, surface the operator-facing conditional where
operators read it.
