// Artifact provenance record.
//
// A #SignedArtifact captures everything strike knows about an
// artifact after pack + sign + SBOM generation + optional Rekor
// submission. This is the unit of trust that flows from build
// into deploy attestations.
//
// Rekor types (#RekorEntry, #InclusionProof) are defined in lane.cue
// and re-exported here so the deploy package can reference them
// without duplication.

package deploy

import "github.com/istr/strike/specs:lane"

// Re-export Rekor types from lane for use within the deploy package.
// attestation.cue references #RekorEntry -- this alias keeps the name
// available without duplicating the definition.
#RekorEntry:    lane.#RekorEntry
#InclusionProof: lane.#InclusionProof

// SignedArtifact is the provenance record for one artifact.
#SignedArtifact: {
	// digest is the content-addressed manifest digest.
	digest: #Digest

	// signature holds the signing record when the artifact was signed.
	signature?: #SignatureRecord

	// sbom holds SBOM metadata when an SBOM was generated.
	sbom?: #SBOMRecord

	// rekor holds the transparency log entry from a hashedrekord
	// submission for this artifact's signature.
	rekor?: #RekorEntry
}

#SignatureRecord: {
	// algorithm identifies the signing algorithm.
	algorithm: "ECDSA-P256-SHA256"

	// payload is the base64-encoded signed payload (cosign format).
	payload: string

	// annotations are the key-value pairs attached to the signature.
	annotations: [string]: string
}

#SBOMRecord: {
	// format is the SBOM standard used.
	format: "cyclonedx-json" | "spdx-json"

	// digest is the content hash of the SBOM document.
	digest: #Digest
}
