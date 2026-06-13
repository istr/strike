# ADR-043: Retire Keyed Image Signing and Rekor v1

## Status

Accepted.

## Context

strike carried two independent signing models. The deploy step produces keyless
attestations -- Fulcio-issued ephemeral certificate, Rekor v2 transparency log,
RFC3161 timestamp -- assembled into Sigstore v0.3 bundles and verified offline by
`internal/verify` and by `cosign` / SLSA verifiers (ADR-039, ADR-040). The pack
step carried a second, older model: a cosign-format keyed signature over the
image manifest digest, submitted to a Rekor v1 transparency log as a
`hashedrekord` entry, with the entry mirrored into the artifact record
(`#Artifact.rekor`, `deploy.#SignedArtifact.rekor`) and tracked by a `signed`
boolean.

The keyed pack signature has no verifying consumer. `strike verify` consumes
keyless deploy bundles only. The single in-tree check that read the pack
signature -- `guardUnsignedImages` -- inspected the `signed` boolean, never the
signature itself: a self-asserted annotation, not a cryptographic gate. Pack
outputs are intermediates in the lane DAG; a lane cannot subject an intermediate
to `strike verify`, so a keyed signature on an intermediate reaches no
verification path at all. Maintaining the model meant carrying a Rekor v1 REST
client, cosign-format key decryption (scrypt + NaCl secretbox), a SET
verification path, and a parallel attestation-signing helper (`SignAttestation`)
-- all of it dead weight against the project's threat model and a standing
supply-chain liability.

## Decision

Remove the keyed image-signing model and the Rekor v1 surface in full.

- Delete the keyed signer (`executor.SignManifest`, `SignPayload`, cosign-format
  key loading) and the Rekor v1 REST client (`executor.RekorClient`: the
  `hashedrekord` / `dsse` submission, SET verification, and response parsing).
- Drop `SigningKey`, `KeyPassword`, and `Rekor` from the pack options, and the
  `cosign_key` / `cosign_password` secret resolution.
- Remove `guardUnsignedImages` and the `signed` boolean. Image inputs are
  admitted on their pinned digest; the boolean gated nothing cryptographic.
- Remove the keyed attestation-signing helper (`SignAttestation`, `signDSSE`)
  and the internal collect-model payload type. The DSSE envelope shape, the PAE
  encoding, and the keyless deploy path are unaffected and retained.
- Remove the `#RekorEntry` / `#InclusionProof` CUE definitions, the artifact
  `rekor` and `signed` fields, and `#SignedArtifact.signature` / `.rekor`.
  `#SignedArtifact` keeps its digest and its SBOM record.

Pack outputs are unsigned intermediates. Their integrity in the chain comes from
the recorded manifest digest, pinned by consuming steps -- the property pack
provenance has always actually rested on.

## Consequences

- Pack steps no longer emit a manifest signature or a Rekor entry. The OCI
  layout written by pack no longer carries a signature manifest.
- A signed, independently verifiable intermediate -- should a consumer for one
  ever materialize -- is a future keyless arc (an ADR-039-level change reusing
  the Fulcio / Rekor v2 / TSA machinery), not a revival of the keyed model.
- `deploy.#SignedArtifact` is now a digest-plus-SBOM record; its name is a
  residual misnomer, left for a separate cleanup.
- The `deploy` package no longer imports `executor`.

## Principles

- Code is liability (a signing model with no verifying consumer is pure attack
  surface and maintenance cost).
- Runtime is attested (the surviving attestation path is keyless and offline-
  verifiable; ADR-040).
- External references are digest-pinned (pack-output integrity rests on the
  pinned manifest digest, not on a signature).
- Enforcement is structural, not discretionary (a boolean that gates nothing
  cryptographic is documentation pretending to be enforcement; removed).
