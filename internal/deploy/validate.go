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

// deploySchema combines the attestation, artifact, and lane CUE schemas.
// All three are compiled together via string concatenation so that types
// like #SignedArtifact and #RekorEntry are available when validating
// #Attestation.
//
// artifact.cue uses `import "github.com/istr/strike/specs:lane"` for
// the `cue export` toolchain, but ctx.CompileString cannot resolve module
// imports. stripForConcat removes package declarations, import blocks,
// and cross-package re-export lines so the files can be concatenated
// into a single CUE source. lane.cue provides #RekorEntry and
// #InclusionProof directly.
var deploySchema = specs.AttestationSchema + "\n" +
	stripForConcat(specs.ArtifactSchema) + "\n" +
	stripForConcat(specs.LaneSchema) + "\n" +
	stripForConcat(specs.ProvenanceSchema)

// stripForConcat removes package declarations, import blocks, and
// cross-package re-export lines (e.g. "#Foo: pkg.#Foo") from a CUE
// source string so it can be concatenated with other CUE sources for
// single-string compilation.
func stripForConcat(src string) string {
	var lines []string
	inImport := false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			continue
		}
		// Single-line import: import "..."
		if strings.HasPrefix(trimmed, "import \"") {
			continue
		}
		// Multi-line import block: import ( ... )
		if trimmed == "import (" {
			inImport = true
			continue
		}
		if inImport {
			if trimmed == ")" {
				inImport = false
			}
			continue
		}
		// Re-export lines referencing another CUE package (e.g. lane.#RekorEntry)
		if strings.Contains(line, "lane.#") {
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
