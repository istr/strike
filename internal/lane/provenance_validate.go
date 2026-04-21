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
// for the declared type, and returns the typed ProvenanceRecord.
func ValidateProvenance(declaredType string, raw []byte) (ProvenanceRecord, error) {
	schema, ok := provenanceSchemas[declaredType]
	if !ok {
		return nil, fmt.Errorf("unknown provenance type %q", declaredType)
	}

	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}

	recordType, _ := probe["type"].(string) //nolint:errcheck // type assertion, not error
	if recordType != declaredType {
		return nil, fmt.Errorf("record type %q does not match declared type %q", recordType, declaredType)
	}

	rec := provenanceCtx.CompileBytes(raw)
	if rec.Err() != nil {
		return nil, fmt.Errorf("invalid record: %w", rec.Err())
	}
	unified := schema.Unify(rec)
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		return nil, fmt.Errorf("schema validation: %w", err)
	}

	return unmarshalProvenanceRecord(declaredType, raw)
}

func unmarshalProvenanceRecord(typ string, raw []byte) (ProvenanceRecord, error) {
	switch typ {
	case "git":
		var r GitProvenanceRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode git record: %w", err)
		}
		return r, nil
	case "tarball":
		var r TarballProvenanceRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode tarball record: %w", err)
		}
		return r, nil
	case "oci":
		var r OCIProvenanceRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode oci record: %w", err)
		}
		return r, nil
	case "url":
		var r URLProvenanceRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode url record: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("unknown provenance type %q", typ)
	}
}
