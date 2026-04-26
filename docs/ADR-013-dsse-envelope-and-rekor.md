# ADR-013: DSSE Envelope Shape and Rekor Submission

## Status

Accepted.

## Context

A signed attestation is more than a digital signature appended to a
JSON document. It needs a wire format that supports verification by
parties that did not produce it, a payload type identifier that
prevents cross-protocol confusion, and a transparency anchor that
proves the signature was made before some point in time.

The Sigstore ecosystem has converged on three pieces:

- **DSSE envelopes** (Dead Simple Signing Envelope, in-toto spec).
  The envelope wraps a payload with a `payloadType` URI and one or
  more signatures over a canonical pre-authentication encoding.
  Cross-protocol confusion is prevented by binding the signature to
  the payload type.
- **Rekor transparency log.** Sigstore's append-only log; an entry
  there is signed by Rekor (a Signed Entry Timestamp, SET) and
  becomes a public proof that the signing happened by a certain
  time.
- **OCI 1.1 referrers.** SBOM and attestation artifacts attached to
  OCI images by reference, discoverable via the referrers API.

strike participates in this ecosystem. Inventing a parallel format
would isolate strike from existing verifiers and force every consumer
to learn a strike-specific shape. The cost of using DSSE is one
envelope wrapper; the benefit is interoperability with everything
else in the supply chain.

The fields in the DSSE envelope have an implication for the
attestation Rekor stores: anything embedded in `attestation.Rekor`
*after* signing is not in the signed payload. If a verifier strips
the `Rekor` field and recomputes the DSSE signature check against
the rest, the check must succeed. This makes `Rekor` proof-of-log
metadata, not part of the signed claim.

## Decision

Every signed deploy attestation in strike is a DSSE envelope:

- `payloadType`: `application/vnd.strike.attestation+json`. A
  strike-specific URI that prevents a strike attestation from being
  mistaken for a generic in-toto Statement during verification.
- `payload`: the base64-encoded canonical JSON of the attestation
  *without* its `Rekor` field. The exclusion is deliberate.
- `signatures`: one or more entries, each carrying a key reference
  and an ECDSA P-256 signature over the DSSE pre-authentication
  encoding (per ADR-008).

The signed envelope is then submitted to Rekor:

- Phase 1 (current): a `hashedrekord` entry containing the
  signature and a hash of the payload. Rekor stores metadata; the
  full envelope stays with the attestation consumer.
- Phase 2 (planned): a `dsse` entry containing the full envelope.
  Rekor becomes the source of truth for both signature and payload.

After Rekor accepts the entry, strike captures:

- `LogIndex`, `LogID`, `IntegratedTime` from the response.
- `SignedEntryTimestamp`: Rekor's SET, signed by the Rekor public
  key, proving inclusion at the recorded time.
- `InclusionProof`: a Merkle inclusion proof for offline
  verification of the entry's presence in the log.

These are stored in `Attestation.Rekor`. The field is set after
signing and is not part of the signed payload, by design: a verifier
strips it before recomputing the DSSE check.

Rekor SET verification is mandatory: a failed SET check is a hard
error, not a transient warning. A forged Rekor response would
otherwise allow a fake transparency proof to slip through. Transient
failures (network errors, 5xx) are warnings: strike fail-opens to
allow deploys to proceed when the log is unavailable. Per-deploy
DSSE envelopes over the 100KB Rekor upload limit are skipped with a
warning, not silently truncated.

## Consequences

- A verifier with the public key can validate a strike attestation
  using any DSSE-compatible library, without strike-specific code.
- The `Rekor` field can be stripped, rewritten, or replaced (e.g.
  if the deploy is later re-logged to a different transparency
  service) without invalidating the original signature. This is a
  feature, not a bug.
- The choice of `application/vnd.strike.attestation+json` as the
  payload type means a verifier explicitly opts into the strike
  schema; attempts to feed a strike attestation to a verifier
  expecting `application/vnd.in-toto+json` fail with a clear
  payload-type mismatch.
- Rekor submission failures fall into two categories with different
  treatment: transient (network, 5xx) is fail-open with a warning,
  forged response (SET verification failure) is fail-closed with
  an error. Treating them the same would mask attacks.
- Migration from Phase 1 (hashedrekord) to Phase 2 (dsse) is a
  transparency-log content change but not a wire-format change for
  attestations themselves.

## Principles

- Runtime is attested
- Code is liability (use DSSE rather than invent a parallel format)
- External references are digest-pinned (payload hash and Rekor
  log entries are content-addressed)
- Identity is asymmetric (signing key in DSSE signatures vs. Rekor
  public key for SET verification, kept distinct)
