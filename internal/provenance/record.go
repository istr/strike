// Package provenance holds the concept-tier source-provenance record types
// (ADR-048). The Git, Tarball, OCI, and URL variant structs are generated from
// contract/provenance/provenance.cue; this file adds the Record
// discriminated-union interface and the shared discriminator method.
package provenance

// Record is the interface implemented by all provenance record types (Git,
// Tarball, OCI, URL). The CUE disjunction is annotated @go(-) so the generator
// skips it; this hand-written interface provides the Go-side discriminated
// union.
type Record interface {
	// ProvenanceType returns the discriminator ("git", "tarball", "oci", "url").
	ProvenanceType() SourceType
}

// ProvenanceType implements Record.
func (r Git) ProvenanceType() SourceType { return r.Type }

// ProvenanceType implements Record.
func (r Tarball) ProvenanceType() SourceType { return r.Type }

// ProvenanceType implements Record.
func (r OCI) ProvenanceType() SourceType { return r.Type }

// ProvenanceType implements Record.
func (r URL) ProvenanceType() SourceType { return r.Type }
