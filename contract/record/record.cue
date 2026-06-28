// Artifact provenance records -- the unit of trust that flows from build into
// deploy attestations. An #Artifact captures what strike knows about an
// artifact after pack and SBOM generation: its content-addressed manifest
// digest and, when generated, SBOM metadata. The wire shape is validated and
// the Go types are generated from it, so there is one source.
package record

import "github.com/istr/strike/contract/primitive"

// #Artifact is the provenance record for one artifact.
#Artifact: {
	@go(Artifact)

	// sbom holds SBOM metadata when an SBOM was generated.
	sbom?: #SBOM @go(SBOM,optional=nillable)

	// digest is the content-addressed manifest digest.
	digest: primitive.#Digest @go(Digest)
}

// #SBOM is SBOM metadata for an artifact.
#SBOM: {
	@go(SBOM)

	// format is the SBOM standard used.
	format: "cyclonedx-json" | "spdx-json" @go(Format)

	// digest is the content hash of the SBOM document.
	digest: primitive.#Digest @go(Digest)
}
