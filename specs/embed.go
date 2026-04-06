// Package specs embeds the CUE schema definitions for lane and attestation
// validation. These are the single source of truth for both input (lane YAML)
// and output (deploy attestation) contracts.
package specs

import _ "embed"

// LaneSchema is the embedded CUE schema for lane definitions.
//
//go:embed lane.cue
var LaneSchema string

// AttestationSchema is the embedded CUE schema for deploy attestations.
//
//go:embed attestation.cue
var AttestationSchema string

// ArtifactSchema is the embedded CUE schema for artifact provenance records.
// Same package deploy as AttestationSchema -- must be compiled together.
//
//go:embed artifact.cue
var ArtifactSchema string
