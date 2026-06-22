// Package specs embeds the CUE schema definitions for lane and attestation
// validation. These are the single source of truth for both input (lane YAML)
// and output (deploy attestation) contracts.
package specs

import _ "embed"

// BaseScalarsSchema is the embedded base-scalars layer of the lane schema.
// With BasePeerSchema, BaseTargetSchema, and WireLaneSchema it forms the CUE
// lane schema, split across the base- and wire- layer files (ADR-047). All
// four declare package lane and are compiled together; the runtime
// concatenates them in internal/lane/parse.go and internal/deploy/validate.go.
//
//go:embed base-scalars.cue
var BaseScalarsSchema string

// BasePeerSchema is the embedded base-peer layer of the lane schema (ADR-047);
// see BaseScalarsSchema.
//
//go:embed base-peer.cue
var BasePeerSchema string

// BaseTargetSchema is the embedded base-target layer of the lane schema
// (ADR-047); see BaseScalarsSchema.
//
//go:embed base-target.cue
var BaseTargetSchema string

// WireLaneSchema is the embedded wire-lane layer of the lane schema (ADR-047);
// see BaseScalarsSchema.
//
//go:embed wire-lane.cue
var WireLaneSchema string

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

// BundleSchema is the embedded CUE schema for the published sigstore bundle
// (v0.3) -- the producer emission contract validated at sign time. Same
// package deploy as AttestationSchema.
//
//go:embed sigstore-bundle.cue
var BundleSchema string

// TrustLayersSchema is the embedded single-source trust-layer map
// (specs/trust-layers.cue). It is data, not a validation schema: the
// conformance test asserts attestation.cue and predicate.cue agree with it.
//
//go:embed trust-layers.cue
var TrustLayersSchema string
