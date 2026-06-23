package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/schema"
)

// ValidateProvenance validates raw JSON against the CUE schema for the
// declared type and returns the typed ProvenanceRecord. The schema-side
// checks run in internal/schema; the typed unmarshal stays here, where the
// record types are defined.
func ValidateProvenance(declaredType string, raw []byte) (ProvenanceRecord, error) {
	if err := schema.ValidateProvenanceJSON(declaredType, raw); err != nil {
		return nil, err
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
