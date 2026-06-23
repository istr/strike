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
		manifest_digest: =~"^sha256:[a-f0-9]{64}$"
		config_digest:   =~"^sha256:[a-f0-9]{64}$"
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
		image_digest: =~"^sha256:[a-f0-9]{64}$"
		input_hashes: [string]:  =~"^sha256:[a-f0-9]{64}$"
		source_hashes: [string]: =~"^sha256:[a-f0-9]{64}$"
	}
	expected: {
		hash: =~"^sha256:[a-f0-9]{64}$"
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
		digest: =~"^sha256:[a-f0-9]{64}$"
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
