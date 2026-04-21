package lane

import (
	"encoding/json"
	"fmt"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"

	"github.com/istr/strike/specs"
)

var (
	provenanceCtx     *cue.Context
	provenanceSchemas map[string]cue.Value
)

func init() {
	provenanceCtx = cuecontext.New()
	schemaFile := provenanceCtx.CompileString(specs.ProvenanceSchema)
	if schemaFile.Err() != nil {
		panic(fmt.Sprintf("provenance schema does not compile: %v", schemaFile.Err()))
	}
	provenanceSchemas = map[string]cue.Value{
		"git":     schemaFile.LookupPath(cue.ParsePath("#GitProvenanceRecord")),
		"tarball": schemaFile.LookupPath(cue.ParsePath("#TarballProvenanceRecord")),
		"oci":     schemaFile.LookupPath(cue.ParsePath("#OCIProvenanceRecord")),
		"url":     schemaFile.LookupPath(cue.ParsePath("#URLProvenanceRecord")),
	}
	for name, v := range provenanceSchemas {
		if !v.Exists() {
			panic(fmt.Sprintf("provenance schema %q not found", name))
		}
	}
}

// ValidateProvenance parses raw JSON, validates it against the CUE schema
// for the declared type, and returns a canonical StepProvenance.
func ValidateProvenance(declaredType string, raw []byte) (StepProvenance, error) {
	schema, ok := provenanceSchemas[declaredType]
	if !ok {
		return StepProvenance{}, fmt.Errorf("unknown provenance type %q", declaredType)
	}

	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return StepProvenance{}, fmt.Errorf("not valid JSON: %w", err)
	}

	recordType, _ := probe["type"].(string) //nolint:errcheck // type assertion, not error
	if recordType != declaredType {
		return StepProvenance{}, fmt.Errorf("record type %q does not match declared type %q", recordType, declaredType)
	}

	rec := provenanceCtx.CompileBytes(raw)
	if rec.Err() != nil {
		return StepProvenance{}, fmt.Errorf("invalid record: %w", rec.Err())
	}
	unified := schema.Unify(rec)
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		return StepProvenance{}, fmt.Errorf("schema validation: %w", err)
	}

	canonical, err := json.Marshal(probe)
	if err != nil {
		return StepProvenance{}, fmt.Errorf("canonicalize: %w", err)
	}
	return StepProvenance{Type: declaredType, Raw: canonical}, nil
}

// IsSigned returns true iff the record contains a signature with verified=true.
func (r StepProvenance) IsSigned() bool {
	var probe struct {
		Signature *struct {
			Verified bool `json:"verified"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(r.Raw, &probe); err != nil {
		return false
	}
	return probe.Signature != nil && probe.Signature.Verified
}
