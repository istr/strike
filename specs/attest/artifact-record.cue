// Artifact provenance record.
//
// An #ArtifactRecord captures everything strike knows about an
// artifact after pack + SBOM generation. This is the unit of
// trust that flows from build into deploy attestations.

package attest

import "github.com/istr/strike/specs/spec"

// ArtifactRecord is the provenance record for one artifact.
#ArtifactRecord: {
	// digest is the content-addressed manifest digest.
	digest: spec.#Digest

	// sbom holds SBOM metadata when an SBOM was generated.
	sbom?: #SBOMRecord
}

#SBOMRecord: {
	// format is the SBOM standard used.
	format: "cyclonedx-json" | "spdx-json"

	// digest is the content hash of the SBOM document.
	digest: spec.#Digest
}
