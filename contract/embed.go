// Package contract embeds the CUE schema definitions for lane and attestation
// validation. These are the single source of truth for both input (lane YAML)
// and output (deploy attestation) contracts. The schemas are loaded natively
// as a CUE module by internal/schema; this package only provides the embedded
// file set. See docs/ADR-048-contract-type-semantics.md.
package contract

import "embed"

// FS holds the embedded CUE contract files, one CUE package per subdirectory.
// internal/schema presents them as a CUE module tree and loads each package
// natively via cue/load.
//
//go:embed lane attest crossval trustlayers primitive endpoint provenance target record
var FS embed.FS
