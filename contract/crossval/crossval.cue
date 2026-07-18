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

import "github.com/istr/strike/contract/primitive"

// #Vector is the union of all cross-validation test vector shapes, each
// discriminated by its concrete boundary literal.
#Vector: (#AssembleVector | #SpecHashVector | #AttestationVector |
	#StateDigestVector | #RenderKnownHostsVector) @go(-)

#AssembleVector: {
	boundary:    "AssembleImage"
	description: string
	inputs: {
		// "oci:empty" or "oci:layout" (with inline manifest).
		base: string
		// PackSpec fields (subset used by AssembleImage).
		spec: _
		// ref -> {content_base64, mode}.
		files: [string]: {
			content_base64: string
			mode:           int
		}
	}
	expected: {
		manifest_digest: primitive.#Digest
		config_digest:   primitive.#Digest
		layer_count:     int & >=0
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
		captures: [...{
			name:          string
			image:         string
			output_base64: string
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
		peers: [...]
	}
	expected: {
		content_base64: string
	}
}
