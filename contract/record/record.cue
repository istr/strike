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

	// sbom holds the digests of the SBOM documents generated over this
	// artifact, both formats together (ADR-051 D3/D9). Absent when the
	// deploy generated no SBOM for it (a kubernetes deploy today).
	sbom?: #SBOMSet @go(SBOM,optional=nillable)

	// digest is the artifact's content identity, computed by the control
	// plane when the artifact was produced: the manifest digest for a step
	// image, the uncompressed-content layer digest (diff_id) for a file or
	// directory output region (ADR-051 D9, ADR-046).
	digest: primitive.#Digest @go(Digest)
}

// #SBOMSet carries the content digests of the two SBOM documents strike
// generates together over one artifact: CycloneDX and SPDX 2.3 JSON. The
// producer emits the pair, so both fields are required whenever the block
// is present (ADR-051 D3).
#SBOMSet: {
	@go(SBOMSet)

	// cyclonedx is the sha256 content digest of the CycloneDX JSON document.
	cyclonedx: primitive.#Digest @go(CycloneDX)

	// spdx is the sha256 content digest of the SPDX JSON document.
	spdx: primitive.#Digest @go(SPDX)
}
