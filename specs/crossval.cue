// Cross-validation test vector schema.
//
// This schema defines the format for self-contained test vectors
// that verify identical behavior across implementations (Go, Rust).
// Each vector file contains both inputs and expected outputs.
//
// This is a development-time specification, NOT embedded in the binary.

package crossval

// Shared envelope for all cross-validation test vectors.
#Vector: {
	boundary:    "AssembleImage" | "SpecHash" | "SignManifest" | "ValidateAttestation" | "SignAttestation"
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
		image_digest:  =~"^sha256:[a-f0-9]{64}$"
		input_hashes:  [string]: =~"^sha256:[a-f0-9]{64}$"
		source_hashes: [string]: =~"^sha256:[a-f0-9]{64}$"
	}
	expected: {
		hash: =~"^sha256:[a-f0-9]{64}$"
	}
}

#SignVector: #Vector & {
	boundary: "SignManifest"
	inputs: {
		manifest_digest: =~"^sha256:[a-f0-9]{64}$"
		// key_pem is injected at test time (ephemeral key).
		key_pem?:  string
		password:  string | null
	}
	expected: {
		// Payload MUST match byte-for-byte across implementations.
		payload: string
		verify: {
			algorithm: "ECDSA-P256-SHA256"
			// public_key_der_base64 is derived at test time from the ephemeral key.
			public_key_der_base64?: string
		}
	}
}

#SignAttestationVector: #Vector & {
	boundary: "SignAttestation"
	inputs: {
		attestation_json: string
		// key_pem is injected at test time (ephemeral key).
		key_pem?:  string
		password:  string | null
	}
	expected: {
		payload_type:          "application/vnd.strike.attestation+json"
		payload_matches_input: true
		verify: {
			algorithm: "ECDSA-P256-SHA256"
			// public_key_der_base64 is derived at test time from the ephemeral key.
			public_key_der_base64?: string
		}
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
