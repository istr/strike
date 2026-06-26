// Cross-validation test vector schema.
//
// This schema defines the format for self-contained test vectors
// that verify identical behavior across implementations (Go, Rust).
// Each vector file contains both inputs and expected outputs.
//
// This is a development-time specification, NOT embedded in the binary.
//
// The cross-implementation harness these vectors exist for is only
// partial and still to come: the vectors are schema-validated and run
// through the Go implementation, but no second implementation exists
// yet, so the cross-implementation comparison is unbuilt.

package crossval

import "github.com/istr/strike/specs/spec"

// Shared envelope for all cross-validation test vectors.
#Vector: {
	boundary:    "AssembleImage" | "SpecHash" | "ValidateAttestation" | "StateDigest" | "RenderKnownHosts"
	description: string
	inputs:      _
	expected:    _
}

#AssembleVector: #Vector & {
	boundary: "AssembleImage"
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
		manifest_digest: spec.#Digest
		config_digest:   spec.#Digest
		layer_count:     int & >=0
	}
}

#SpecHashVector: #Vector & {
	boundary: "SpecHash"
	inputs: {
		step: {
			args: [...string]
			env: [string]: string
		}
		image_digest: spec.#Digest
		input_hashes: [string]:  spec.#Digest
		source_hashes: [string]: spec.#Digest
	}
	expected: {
		hash: spec.#Digest
	}
}

#AttestationVector: #Vector & {
	boundary: "ValidateAttestation"
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

#StateDigestVector: #Vector & {
	boundary: "StateDigest"
	inputs: {
		captures: [...{
			name:          string
			image:         string
			output_base64: string
		}]
	}
	expected: {
		digest: spec.#Digest
	}
}

#RenderKnownHostsVector: #Vector & {
	boundary: "RenderKnownHosts"
	inputs: {
		peers: [...]
	}
	expected: {
		content_base64: string
	}
}
