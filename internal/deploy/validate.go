package deploy

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/schema"
)

// ValidateAttestation checks a serialized attestation against the embedded
// CUE schema. This ensures that the attestation output -- the document that
// carries the supply chain trust chain -- conforms to the formal specification.
//
// This mirrors lane.Parse's CUE validation of input (lane YAML) but covers
// the output side. Together they provide a complete CUE-defined contract:
//
//	lane.yaml -> CUE validate (input)  -> execute -> attestation -> CUE validate (output)
func ValidateAttestation(att *Attestation) error {
	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation for validation: %w", err)
	}
	return ValidateAttestationJSON(data)
}

// ValidateAttestationJSON validates raw JSON bytes against the attestation
// CUE schema. This is the cross-validation boundary: any implementation can
// serialize an attestation to JSON and validate it against the same schema.
func ValidateAttestationJSON(data []byte) error {
	return schema.ValidateAttestationJSON(data)
}

// ValidateBundleJSON validates a marshaled sigstore bundle against the embedded
// #Bundle schema (contract/attest/bundle.cue). It is the producer emission
// guard: assembleKeylessBundle calls it before returning, so a bundle that does
// not conform to strike's published wire contract is never emitted. The
// consumer side (internal/verify) is intentionally not narrowed to this schema:
// it parses arbitrary sigstore bundles via sigstore-go.
func ValidateBundleJSON(data []byte) error {
	return schema.ValidateBundleJSON(data)
}
