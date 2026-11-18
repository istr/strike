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

	// sbom holds the digest of the SBOM document generated over this
	// artifact (ADR-051 D3/D9, ADR-059 D1). Absent when the deploy generated
	// no SBOM for it (a kubernetes deploy today).
	sbom?: #SBOMSet @go(SBOM,optional=nillable)

	// digest is the artifact's content identity, computed by the control
	// plane when the artifact was produced: the manifest digest for a step
	// image, the uncompressed-content layer digest (diff_id) for a file or
	// directory output region (ADR-051 D9, ADR-046).
	digest: primitive.#Digest @go(Digest)
}

// #SBOMSet carries the content digest of the SBOM document strike generates
// over one artifact: a CycloneDX JSON document in canonical form (ADR-051
// D3, ADR-059 D2). The sealed statement names the document by this digest
// (ADR-059 D1).
#SBOMSet: {
	@go(SBOMSet)

	// cyclonedx is the sha256 content digest of the CycloneDX JSON document.
	cyclonedx: primitive.#Digest @go(CycloneDX)
}

// #TrustLayer is the trust a verifier must supply to rely on an attested fact,
// and the layer a published statement bundle carries (ADR-037). sealed is sound
// to any verifier without engine trust; engine-dependent is sound only to a
// verifier who trusts the engine; informational puts forward no trust claim.
#TrustLayer: "sealed" | "engine-dependent" | "informational"
