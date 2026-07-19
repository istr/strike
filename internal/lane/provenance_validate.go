package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/schema"
)

// ValidateProvenance validates raw JSON against the CUE schema for the
// declared type and returns the typed provenance.Record. The schema-side
// checks run in internal/schema; the typed unmarshal stays in this services
// package, which may import both the schema (foundation) and provenance
// (concept) packages. schema is a foundation package that must not import
// internal/lane (ADR-048), so SourceType is narrowed to a plain string only
// at that boundary call.
func ValidateProvenance(declaredType provenance.SourceType, raw []byte) (provenance.Record, error) {
	typeStr := string(declaredType)
	if err := schema.ValidateProvenanceJSON(typeStr, raw); err != nil {
		return nil, err
	}
	return unmarshalProvenanceRecord(declaredType, raw)
}

func unmarshalProvenanceRecord(typ provenance.SourceType, raw []byte) (provenance.Record, error) {
	switch typ {
	case provenance.SourceTypeGit:
		var r provenance.Git
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode git record: %w", err)
		}
		return r, nil
	case provenance.SourceTypeTarball:
		var r provenance.Tarball
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode tarball record: %w", err)
		}
		return r, nil
	case provenance.SourceTypeOci:
		var r provenance.OCI
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode oci record: %w", err)
		}
		return r, nil
	case provenance.SourceTypeUrl:
		var r provenance.URL
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode url record: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("unknown provenance type %q", typ)
	}
}
