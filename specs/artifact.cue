// Artifact provenance record.
//
// A #SignedArtifact captures everything strike knows about an
// artifact after pack + SBOM generation. This is the unit of
// trust that flows from build into deploy attestations.

package deploy

import "github.com/istr/strike/specs:lane"

// Re-export types from lane for use within the deploy package.
// attestation.cue references these -- aliases keep the names
// available without duplicating the definitions.
// The exported JSON Schema inlines all $defs, so the output
// remains self-contained for external verifiers (ADR-004).
#Digest:           lane.#Digest
#AbsPath:          lane.#AbsPath
#Identifier:       lane.#Identifier
#ProvenanceRecord: lane.#ProvenanceRecord
#DeployTarget:     lane.#DeployTarget
#Peer:             lane.#Peer
#HTTPSPeer:        lane.#HTTPSPeer
#SSHPeer:          lane.#SSHPeer
#TLSTrust:         lane.#TLSTrust
#FingerprintTrust: lane.#FingerprintTrust
#CABundleTrust:    lane.#CABundleTrust
#KnownHostEntry:   lane.#KnownHostEntry

// SignedArtifact is the provenance record for one artifact.
#SignedArtifact: {
	// digest is the content-addressed manifest digest.
	digest: #Digest

	// sbom holds SBOM metadata when an SBOM was generated.
	sbom?: #SBOMRecord
}

#SBOMRecord: {
	// format is the SBOM standard used.
	format: "cyclonedx-json" | "spdx-json"

	// digest is the content hash of the SBOM document.
	digest: #Digest
}
