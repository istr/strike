package deploy

import (
	"encoding/json"
	"fmt"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
	"github.com/istr/strike/specs"
)

var attestationSchema = specs.AttestationSchema

// ValidateAttestation checks a serialized attestation against the embedded
// CUE schema. This ensures that the attestation output — the document that
// carries the supply chain trust chain — conforms to the formal specification.
//
// This mirrors lane.Parse's CUE validation of input (lane YAML) but covers
// the output side. Together they provide a complete CUE-defined contract:
//
//	lane.yaml → CUE validate (input)  → execute → attestation → CUE validate (output)
func ValidateAttestation(att *Attestation) error {
	data, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation for validation: %w", err)
	}
	return ValidateAttestationJSON(data)
}

// ValidateAttestationJSON validates raw JSON bytes against the attestation
// CUE schema. This is the cross-validation boundary: any implementation
// can serialize an attestation to JSON and validate it against the same schema.
func ValidateAttestationJSON(data []byte) error {
	ctx := cuecontext.New()

	compiled := ctx.CompileString(attestationSchema).
		LookupPath(cue.ParsePath("#Attestation"))

	expr, err := cuejson.Extract("attestation.json", data)
	if err != nil {
		return fmt.Errorf("extract attestation JSON: %w", err)
	}

	unified := compiled.Unify(ctx.BuildExpr(expr))
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		return fmt.Errorf("attestation schema violation:\n%w", err)
	}
	return nil
}
