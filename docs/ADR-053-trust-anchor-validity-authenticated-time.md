# ADR-053: Trust-anchor validity is bound to an authenticated time

## Status

Accepted. Sharpens the verification half of
[ADR-040](ADR-040-control-plane-sbom-and-keyless-attestation.md)
(keyless chain) and is consistent with
[ADR-008](ADR-008-cryptographic-primitives.md) (one curve, one hash)
and [ADR-015](ADR-015-internal-clock-dispatch.md) (all time access
dispatched through `internal/clock`). ADR-015 governs which clock a
call site reads; this ADR governs which time a trust decision is
evaluated against, and those are different questions.

## Context

A sigstore trusted root is a set of anchors: Fulcio certificate
authorities, timestamp authorities, Rekor transparency-log keys, and
certificate-transparency log keys. Every one of them carries a
declared validity window -- `validFor` on the certificate chains,
`publicKey.validFor` on both classes of log key. The window exists so
that a rotated or withdrawn anchor stops certifying material it was
never meant to cover.

A window is only worth as much as the clock it is compared against.
If the reference time can be chosen by whoever produced the bundle,
the window bounds nothing: an attacker who can name the time can name
one inside the window. So the question a verifier must answer for
each anchor is not "is there a window" but "against which time, and
who signed that time".

strike's verifier answers this today for two of the four anchor
classes and not for the other two. The Fulcio chain and the TSA chain
are verified with an explicit reference time -- the RFC3161 token
time, which is signed by the timestamp authority and checked before
it is used -- so their windows are enforced through ordinary X.509
chain validation. The Rekor log key is selected by log id alone, with
no window and no time. Certificate-transparency material is not
consumed at all.

The reference implementation shows the same split, which is what
makes it worth recording rather than merely fixing. In sigstore-go
v1.2.0 both log classes are the same Go type carrying the same
`ValidityPeriodStart` and `ValidityPeriodEnd` fields.
`pkg/verify/sct.go` enforces both bounds against the SCT's own
timestamp. `pkg/verify/tlog.go` reads neither field: the Rekor key is
looked up by log id, and the only time comparison in that path is the
entry's `integratedTime` against the leaf certificate's validity,
guarded by a check that skips it when the value is zero.

The split is not carelessness. It follows from what each protocol
signs. An SCT carries its timestamp *inside* the RFC 6962
digitally-signed structure, so forging the time invalidates the SCT
signature -- the CT path has an authenticated time for free. Rekor v2
has none: `integratedTime` is not covered by any signature and is in
practice absent from the bundle, and the C2SP checkpoint body carries
an origin, a tree size, and a root hash, with no time line. A
verifier that will not borrow a time from elsewhere therefore cannot
bind the Rekor key window at all.

strike is in a position to borrow one. It already obtains, verifies,
and relies on an RFC3161 trusted time before it looks at any
certificate. The material the reference implementation lacks is
material strike is already holding.

## Decision

### D1 -- Anchor validity is enforced, never informational

Every anchor drawn from the trusted root -- Fulcio CA, timestamp
authority, Rekor log key, CT log key -- is used only inside its
declared validity window. An anchor outside its window is not a
degraded anchor or a warning; the verification fails closed. An
anchor whose window cannot be evaluated is likewise not usable.

### D2 -- The reference time is authenticated

A validity window is evaluated only against a time whose forgery
invalidates a signature the verifier already checks. Two such times
exist in a strike bundle: the SCT timestamp, covered by the SCT
signature, and the RFC3161 token time, covered by the timestamp
authority's CMS signature. A value carried in the bundle under no
signature is never a validity reference. Concretely, Rekor's
`integratedTime` is not one: it may be read for other purposes, but
it never decides whether an anchor was valid.

### D3 -- An anchor whose protocol signs no time borrows the RFC3161 time

Where the anchor's own protocol supplies no authenticated time, its
window is evaluated against the RFC3161 trusted time already
established for the bundle. This applies to the Rekor v2 log key. The
borrow is stated rather than hidden, because it changes the claim:
the verifier asserts that the log key was valid when the artifact was
signed, not that it was valid when the entry was integrated. That is
a weaker statement than the ideal one and the strongest statement the
available material supports. Closing the remaining gap requires a
signed time from the log, which is an upstream change, not a strike
change.

### D4 -- Reference-implementation parity is a floor, not a ceiling

Where the sigstore reference implementation is stricter than strike,
strike matches it; posture symmetry is a design goal. Where the
reference implementation is weaker because the upstream material it
needs is missing, strike does not inherit the weakness if it holds
that material itself. Divergence in the strict direction is
acceptable and is documented at the point of divergence. Divergence
in the permissive direction is not.

## Consequences

- The parsed trusted material carries each log key together with its
  window, for both log classes, instead of the bare key it carries
  today. The transparency-log inclusion check takes the trusted time
  as an input, since it now has a window to evaluate.
- The CUE replica of the trusted root gains the upper bound of the
  log-key window. The replica is closed, so without it a real trusted
  root that declares an end date is rejected on the inline path --
  a fail-closed rejection of legitimate input, and the reason the
  field is added together with this decision rather than later.
- strike rejects bundles the reference implementation accepts: one
  whose Rekor log key sits outside its declared window is rejected
  here and accepted by cosign. This is D4 in effect and is expected.
- A second implementation must implement D1 through D3 or it is
  silently weaker than strike, because the omission produces a false
  accept rather than a build failure. This is the reason the rule is
  an ADR and not a comment: the cross-implementation contract that
  the CUE-first principle exists to support cannot carry a rule that
  is only visible in one language's source.
- `docs/ADR-INDEX.md` gains this ADR's line.

## Alternatives considered

- **Bind the Rekor key window to `integratedTime`.** Rejected on two
  independent grounds: the value is unsigned, so an attacker who
  supplies the bundle supplies the time; and under Rekor v2 it is
  normally absent, so the check would not run.
- **Leave the Rekor key window unbound, matching the reference
  implementation.** Rejected. The same field on the same type is
  enforced on the CT path, so the asymmetry is a consequence of
  missing upstream material rather than a decision; adopting it would
  make strike's verifier weaker than its own trusted-root schema
  already describes.
- **Treat the window as informational and report rather than
  reject.** Rejected. An anchor that certifies material outside its
  declared window is not an anchor, and a verifier that says so
  without acting on it has moved the decision to the reader.
- **Wait for the log to supply a signed time.** Rejected as a
  precondition. The upstream change is worth pursuing separately, but
  until it lands the choice is between a borrowed authenticated time
  and no binding at all, and no binding is the weaker option.

## Principles

- **Runtime is attested.** The attestation chain is verifiable
  offline only if each anchor in it was valid when it acted; a window
  that is declared but never evaluated leaves that unproven.
- **Enforcement is structural, not discretionary.** The window is
  checked by the verifier on every bundle, not remembered by whoever
  assembles the trusted root.
- **Observation over declaration.** The trusted root *declares* a
  validity window; this decision requires the verifier to *observe*
  it against a time it has independently authenticated.
