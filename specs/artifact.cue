// Artifact provenance record.
//
// A #SignedArtifact captures everything strike knows about an
// artifact after pack + sign + SBOM generation + optional Rekor
// submission. This is the unit of trust that flows from build
// into deploy attestations.

package deploy

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

// RekorEntry holds the transparency log response from a Rekor
// submission (hashedrekord or dsse). When present, all subfields
// are required -- a partial Rekor entry is invalid.
#RekorEntry: {
	// log_index is the global sequence number in the transparency log.
	log_index: int

	// log_id is the hex-encoded hash of the log's public key.
	log_id: =~"^[a-f0-9]{64}$"

	// integrated_time is the Unix timestamp when the entry was added.
	integrated_time: int

	// body is the base64-encoded entry body.
	body: string

	// inclusion_proof holds the Merkle tree proof for this entry.
	inclusion_proof: #InclusionProof
}

#InclusionProof: {
	// log_index is the leaf index in the Merkle tree.
	log_index: int

	// root_hash is the hex-encoded tree root at inclusion time.
	root_hash: =~"^[a-f0-9]{64}$"

	// tree_size is the number of leaves when the proof was generated.
	tree_size: int

	// hashes are the hex-encoded sibling hashes from leaf to root.
	hashes: [...=~"^[a-f0-9]{64}$"]
}
