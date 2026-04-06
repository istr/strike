package deploy

import (
	"encoding/json"
	"fmt"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
	"github.com/istr/strike/specs"
)

// deploySchema combines the attestation and artifact CUE schemas.
// Both files use package deploy and must be compiled together so that
// types like #SignedArtifact are available when validating #Attestation.
// The artifact schema's package declaration is stripped to allow
// concatenation into a single CUE source string.
var deploySchema = specs.AttestationSchema + "\n" + stripPackageLine(specs.ArtifactSchema)

// stripPackageLine removes the "package ..." line from a CUE source string.
func stripPackageLine(src string) string {
	var lines []string
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "package ") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

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

	compiled := ctx.CompileString(deploySchema).
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
