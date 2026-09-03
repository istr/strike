// Cross-validation test vector schema.
//
// This schema defines the format for self-contained test vectors
// that verify identical behavior across implementations (Go, Rust).
// Each vector file contains both inputs and expected outputs.
//
// The schema is embedded in the binary: internal/schema builds a crossval
// root from the embedded contract FS.
//
// The cross-implementation harness these vectors exist for is only
// partial and still to come: the vectors are schema-validated and run
// through the Go implementation, but no second implementation exists
// yet, so the cross-implementation comparison is unbuilt.

package crossval

import (
	"github.com/istr/strike/contract/endpoint"
	"github.com/istr/strike/contract/lane"
	"github.com/istr/strike/contract/primitive"
)

// #Vector is the union of all cross-validation test vector shapes, each
// discriminated by its concrete boundary literal.
#Vector: (#AssembleVector | #SpecHashVector | #AttestationVector |
	#StateDigestVector | #RenderKnownHostsVector) @go(-)

#AssembleVector: {
	boundary:    "AssembleImage"
	description: string
	inputs: {
		// The base image the boundary starts from, stated in wire terms so any
		// implementation constructs it instead of naming a library artifact.
		// The boundary rebuilds the manifest, so the base contributes its media
		// types, its config blob and its layer set, and nothing else.
		base: {
			manifest_media_type: string
			config_media_type:   string
			// config_json_base64 is the base config blob, byte-exact. Its
			// sha256 is the config digest a constructing implementation writes
			// into the base manifest.
			config_json_base64: primitive.#Base64
			// The boundary is defined for a zero-layer base only. A base with
			// layers needs descriptors and blobs, which is a schema change.
			layers: []
		}
		// PackSpec fields (subset used by AssembleImage).
		spec: {
			files: [...lane.#PackFile]
			config?: lane.#ImageConfig
			annotations?: {
				[string]: string
			}
		}
		// ref -> {content_base64, mode}.
		files: [string]: {
			content_base64: primitive.#Base64
			mode:           int
		}
	}
	// expected is normative: every conforming implementation reproduces it.
	expected: {
		// diff_ids is the uncompressed per-layer identity, the only per-layer
		// key that survives a re-encoding (ADR-046). It is also carried inside
		// config_json_base64; the separate list localizes a failure to tar
		// canonicalization rather than to config serialization.
		diff_ids: [...primitive.#Digest]
		// config_json_base64 is the assembled config blob, byte-exact. It
		// encodes reference decisions a second implementation must reproduce,
		// among them the zero creation timestamp and one empty history entry
		// per appended layer; they are stated here, not derived from the OCI
		// image-config specification.
		config_json_base64: primitive.#Base64
	}
	// go_ggcr_reference is NOT normative. These digests are a property of the
	// reference implementation -- the Go standard library's json and flate
	// encoders and the go-containerregistry types layered on them -- not of the
	// boundary. The layer digest inside the manifest covers a compressed blob
	// and DEFLATE output is not specified by compression level, so a second
	// implementation neither reproduces nor checks them; they pin the reference
	// against its own regression (ADR-046).
	go_ggcr_reference: {
		manifest_digest: primitive.#Digest
		config_digest:   primitive.#Digest
	}
}

#SpecHashVector: {
	boundary:    "SpecHash"
	description: string
	inputs: {
		step: {
			args: [...string]
			env: [string]: string
		}
		image_digest: primitive.#Digest
		input_hashes: [string]:  primitive.#Digest
		source_hashes: [string]: primitive.#Digest
	}
	expected: {
		hash: primitive.#Digest
	}
}

#AttestationVector: {
	boundary:    "ValidateAttestation"
	description: string
	inputs: {
		attestation: _
	}
	expected: {
		valid: bool
		if !valid {
			error_contains: string
		}
	}
}

#StateDigestVector: {
	boundary:    "StateDigest"
	description: string
	inputs: {
		// The capture fields carry the grammars the contract already owns. The
		// Go fixture still decodes name and image as plain strings because
		// deploy.NewCaptureSnap takes them that way; typing that producer is
		// item-0080, and the contract leads.
		captures: [...{
			name:          primitive.#Identifier
			image:         primitive.#ImageRef
			output_base64: primitive.#Base64
		}]
	}
	expected: {
		digest: primitive.#Digest
	}
}

#RenderKnownHostsVector: {
	boundary:    "RenderKnownHosts"
	description: string
	inputs: {
		// The front's lane-wide synthetic host key. Every rendered line carries
		// this key and never the peer's own declared key (ADR-038), so the
		// output is undefined without it and it is an input to the boundary
		// rather than a property of the harness.
		front_key: endpoint.#HostKey
		peers: [...lane.#Peer]
	}
	expected: {
		// Empty output is the defined result for a peer set with no ssh peer,
		// which primitive.#Base64 excludes by construction, so this stays a
		// plain string.
		content_base64: string
	}
}
