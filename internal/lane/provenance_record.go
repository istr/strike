package lane

// ProvenanceRecord is the interface implemented by all provenance record
// types (GitProvenanceRecord, TarballProvenanceRecord, OCIProvenanceRecord,
// URLProvenanceRecord). The CUE disjunction is annotated @go(-) so the
// generator skips it; this hand-written interface provides the Go-side
// discriminated union.
type ProvenanceRecord interface {
	// ProvenanceType returns the discriminator ("git", "tarball", "oci", "url").
	ProvenanceType() string
	// IsSigned returns true when the record carries a verified signature.
	IsSigned() bool
}

// ProvenanceType implements ProvenanceRecord.
func (r GitProvenanceRecord) ProvenanceType() string { return r.Type }

// ProvenanceType implements ProvenanceRecord.
func (r TarballProvenanceRecord) ProvenanceType() string { return r.Type }

// ProvenanceType implements ProvenanceRecord.
func (r OCIProvenanceRecord) ProvenanceType() string { return r.Type }

// ProvenanceType implements ProvenanceRecord.
func (r URLProvenanceRecord) ProvenanceType() string { return r.Type }

// IsSigned implements ProvenanceRecord.
func (r GitProvenanceRecord) IsSigned() bool { return r.Signature != nil && r.Signature.Verified }

// IsSigned implements ProvenanceRecord.
func (r TarballProvenanceRecord) IsSigned() bool { return r.Signature != nil && r.Signature.Verified }

// IsSigned implements ProvenanceRecord.
func (r OCIProvenanceRecord) IsSigned() bool { return r.Signature != nil && r.Signature.Verified }

// IsSigned implements ProvenanceRecord.
func (r URLProvenanceRecord) IsSigned() bool { return r.Signature != nil && r.Signature.Verified }
