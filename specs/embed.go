// Package specs embeds the CUE schema definitions for lane and attestation
// validation. These are the single source of truth for both input (lane YAML)
// and output (deploy attestation) contracts. The schemas are loaded natively
// as a CUE module by internal/schema; this package only provides the embedded
// file set. See docs/ADR-047-spec-package-layering.md.
package specs

import "embed"

// FS holds the embedded CUE spec files (the base-, api-, wire-, attest-, and
// meta- layer files). internal/schema presents them as a CUE module tree and
// loads each package natively via cue/load.
//
//go:embed *.cue
var FS embed.FS
