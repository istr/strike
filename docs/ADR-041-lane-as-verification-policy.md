# ADR-041: The lane as verification policy

## Status

Accepted.

## Context

ADR-040 established the keyless attestation producer: every deploy emits
DSSE-signed in-toto statements bound to ephemeral Fulcio identities, logged in
Rekor v2 and timestamped by an RFC3161 TSA. The consumer half -- the offline
verifier that checks such a bundle without contacting strike or the engine --
is what makes "runtime is attested" a checkable promise rather than an
assertion. Building it forces a question the producer never had to answer:
where does a verifier get its trust inputs?

Two inputs can never come from the artifact under verification, because taking
them from it makes verification circular:

- The **signature trust root** -- the Fulcio CA, the Rekor log key, the TSA
  certificate. If it travelled inside the bundle, the bundle would carry its
  own grounds for being trusted, and every self-consistent bundle would
  verify.
- The **expected signer identity and issuer**. They are recorded in the
  bundle's provenance, but checking the bundle against its own recorded
  identity only asks "was this signed by whoever signed it". Anyone with any
  valid OIDC account can mint such a bundle for any artifact. This is the
  failure cosign's mandatory identity and issuer flags exist to prevent.

Everything else a verifier needs is derivable from the artifact reference or
the lane: the bundle (Rekor and OCI referrers at the digest), the subject (the
digest itself), the deploy targets (the lane's deploy methods).

There are two primary verification use cases, and they differ in who holds the
policy:

- **Consumer (UC1).** "I have an image; is its signature valid and from whom I
  expect?" The caller knows only the artifact reference. The two irreducible
  inputs must be supplied explicitly.
- **Operator (UC2).** "I have a lane.yaml; did the artifacts in the target
  registry come from this lane, under the identity it declares?" The caller
  holds the intent and checks the registry against it. This checks strictly
  more than UC1: not only "validly signed" but "produced by this lane" -- a
  claim the sealed statement supports because it carries the lane identity.

A valid lane already declares almost everything UC2 needs. The OIDC signing
identity (issuer, identity) is mandatory in the lane and is carried verbatim
into the sealed provenance. The keyless endpoints are mandatory. What the lane
does not declare is the signature trust root, and the omission is not an
oversight but the asymmetry of the two PKIs involved: the lane declares
**transport anchors** -- the TLS identities under which the producer reaches
Fulcio, Rekor, and the TSA -- while the verifier needs **signature roots** --
the CA and keys that signed the leaf and the log. In the local harness these
are literally different artifacts: the transport anchor is the Caddy root; the
signature roots are exported separately. The producer needs only the transport
anchors (it is issued its leaf over the secured channel); the verifier needs
only the signature roots (it contacts no service). Neither set derives from
the other.

The cosign UX burden is not that these inputs must be external; it is that
cosign has nowhere to declare them and so demands them re-typed on every
invocation. strike has that place: the lane.

## Decision

1. **Two inputs are irreducibly external to the artifact: the signature trust
   root and the expected identity and issuer.** A verifier never sources
   either from the bundle under check.

2. **For the consumer (UC1), both are explicit parameters.** Verifying an
   image reference takes an explicit trust root and explicit identity and
   issuer. The reference is digest-pinned; a tag is a parse error, consistent
   with the digest-pinning principle, because a registry's tag resolution
   could substitute an older, legitimately signed artifact.

3. **For the operator (UC2), the lane is the policy source.** A lane already
   declares the expected identity and issuer; the signature trust root is
   added to the lane, declared **digest-pinned by reference**, so a verifier
   holding the lane needs no further policy input. Verification by lane
   requires no sigstore-shaped flags.

4. **An explicit trust root always overrides the lane-declared one.** The lane
   default serves the operator who trusts their own lane; the override serves
   the consumer who does not, and the auditor who pins an independent root.

5. **The lane is bound to its attestations by lane_digest: the raw sha256 over
   the lane file bytes**, computed by the control plane at parse time over the
   same bytes the parser consumes, and sealed (Layer V). The digest is over
   raw bytes, not a canonical form: no canonicalization machinery in the
   verifier, and the resulting semantics are correct for UC2 -- verification
   is versions-sharp, so artifacts built from an older lane revision fail
   against today's file, and that older revision is what git supplies when it
   is the question being asked.

6. **The producer enforces the declared identity fail-closed.** Before any
   Fulcio contact, the ambient token's subject must equal the lane-declared
   identity, or the deploy aborts. The token is the observation, the
   declaration the expectation; a mismatch is caught at the source rather than
   hours later at the verifier.

7. **The trust placed in the lane file is explicit, not implicit.**
   Parameterless lane verification answers "do the registry artifacts match
   THIS file and the policy IN it". Whoever can edit the lane sets the policy;
   for UC2 that is correct by definition, because the lane is the referent of
   the question. The consumer who cannot make that assumption uses UC1's
   explicit inputs, and an explicit trust root overrides the file in either
   case.

## Consequences

- The lane schema gains a digest-pinned signature-trust-root declaration, and
  the sealed lane_ref field becomes lane_digest, populated for the first time.
  The predicate's hand-mirrored Go types and the crossval fixtures follow.

- This refines ADR-040's stance that the sigstore trust root is purely a
  verification-time parameter: it remains a verification-time input, but the
  lane may now name it, digest-pinned, so a verifier can be handed one file.
  Because the reference is digest-pinned, rotating a trust root is a visible
  lane edit -- which is correct, since changing the roots that ground every
  signature is a policy change, not a configuration tweak.

- The convenience of parameterless UC2 carries a real trust concentration: an
  attacker who can rewrite the lane (identity to their own, roots to their
  own) produces artifacts that match the rewritten file perfectly, and a
  verifier run against that file reports success. With a privately rooted,
  independently supplied trust root, a tampered lane is contained because the
  attacker holds no certificate under that root. The default collapses both
  onto one file; the mitigation is that UC1's explicit inputs remain for the
  distrustful consumer, the override always wins, and the lane belongs under
  review and ideally a signed commit. The positive form of the same fact:
  lane_digest over a git-signed lane is the link from signed commit to
  deployment outcome that the broader ecosystem lacks.

- The registry is not trust-bearing for the verdict. It can withhold a bundle
  (turning a verification into "no attestation found", which is fail-closed)
  but it cannot forge one; a valid verdict requires a cryptographic break, not
  registry cooperation. A consumer-facing verify tool may therefore reach the
  registry over the system CA without weakening the verdict -- a posture
  distinct from the lane's peer egress, where the system CA is an explicit
  opt-in.

- Multiple statements (sealed, engine-context, informational) may hang off one
  digest. The verdict is fail-closed in both directions: the sealed statement
  must be present and valid, every other present statement must be valid, and
  zero bundles is a failure, not a pass.

## Supersedes and extends

Extends ADR-040 (keyless attestation) by defining its consumer half and the
policy inputs verification requires. Refines, without superseding, ADR-040's
note that the sigstore trust root is declared nowhere in the lane: the lane
may now declare it, digest-pinned, as the default UC2 policy source, with an
explicit override.

## Principles

- Runtime is attested -- this ADR defines the consumer that makes the
  attestation checkable offline, closing the producer-to-verifier loop.
- Identity is asymmetric -- the lane's transport anchors (producer-side) and
  the signature roots (verifier-side) are different PKIs; neither derives from
  the other, and the verifier needs only the latter.
- External references are digest-pinned -- the lane-declared trust root is
  pinned by digest, and lane_digest is the content address of the lane file
  itself.
- CUE first -- the lane, defined in CUE, is the policy source; the identity,
  the keyless endpoints, and the trust-root reference are schema, not flags.
- Observation over declaration -- verification observes the registry artifacts
  against the lane's declarations, and the producer's fail-closed identity
  check measures the observed token against the declared identity.
- Enforcement is structural, not discretionary -- the circular inputs cannot
  be sourced from the artifact, and the declared-identity check is fail-closed
  in the signing path, not a verifier-side afterthought.
- Code is liability -- lane_digest is raw bytes with no canonicalization
  machinery, and the verifier reuses the existing core rather than growing a
  parallel path.
