package lane

import (
	"fmt"
	"strings"
)

// Ref returns the canonical "step.output" string form of an output
// reference. This is the single definition of the dotted encoding strike
// uses below the schema boundary: the key under which a producer's
// artifact is registered in and resolved from State, and the input
// identifier folded into the ADR-027 spec hash (and thus every cache tag).
// Every producer and consumer that needs the string form derives it here
// instead of re-spelling step + "." + output.
//
// The encoding is unambiguous only because #Identifier (specs/lane.cue)
// excludes '.', so a Ref string carries exactly one '.' that always splits
// step from output and no two distinct (step, output) pairs collide. That
// grammar property is load-bearing: if #Identifier is ever widened to admit
// '.', this encoding -- and the spec hashes and cache tags built on it --
// must be revisited. TestOutputRef_RefRejectsDottedIdentifier pins it.
func (r OutputRef) Ref() string {
	return r.Step + "." + r.Output
}

// ManifestDigest extracts the manifest digest from an OutputHandle's imageRef.
// imageRef has the form "repo@algorithm:hex"; the digest is everything after
// the "@".
func (h OutputHandle) ManifestDigest() (Digest, error) {
	_, d, ok := strings.Cut(h.ImageRef, "@")
	if !ok {
		return Digest{}, fmt.Errorf("output handle: no digest in image ref %q", h.ImageRef)
	}
	return ParseDigest(d)
}
