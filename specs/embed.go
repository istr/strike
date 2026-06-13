// Package specs embeds the CUE schema definitions for lane and attestation
// validation. These are the single source of truth for both input (lane YAML)
// and output (deploy attestation) contracts.
package specs

import _ "embed"

// LaneSchema is the embedded CUE schema for lane definitions.
//
//go:embed lane.cue
var LaneSchema string

// TrustRootSchema is the embedded CUE replica of the sigstore trusted root.
// Same package lane as LaneSchema -- lane.cue references #TrustedRootReplica,
// so the two must be compiled together for runtime validation.
//
//go:embed sigstore-trustroot.cue
var TrustRootSchema string

// AttestationSchema is the embedded CUE schema for deploy attestations.
//
//go:embed attestation.cue
var AttestationSchema string

// ArtifactSchema is the embedded CUE schema for artifact provenance records.
// Same package deploy as AttestationSchema -- must be compiled together.
//
//go:embed artifact.cue
var ArtifactSchema string

// PredicateSchema is the embedded CUE schema for the output attestation
// predicates (ADR-040 D3). Same package deploy -- must be compiled together.
//
//go:embed predicate.cue
var PredicateSchema string

// ProvenanceSchema is the embedded CUE schema for source provenance records.
// Same package lane as LaneSchema.
//
//go:embed source-provenance.cue
var ProvenanceSchema string

// TransportSchema is the embedded CUE schema for transport-level types
// (host constraint, TLS trust anchors). Same package lane as LaneSchema.
//
//go:embed transport.cue
var TransportSchema string
