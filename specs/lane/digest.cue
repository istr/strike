// Internal digest contract -- the structured, computed digest reference.
//
// DigestRef is the internal computed form of a content-addressed digest: an
// algorithm and a bare hex body, built and read field-wise inside the pipeline.
// It is distinct from the wire form #Digest (a "sha256:<hex>" string in
// scalars.cue): the wire string crosses the serialization boundary,
// DigestRef is what internal code computes with. internal/lane/digest_type.go
// bridges the two (ParseDigest, Wire). See
// docs/ADR-046-one-canonical-digest-pinned-image.md (wire vs internal API) and
// docs/ADR-004-cue-as-single-source-of-truth.md.
//
// Same `package lane` as the other specs files: CUE merges same-package files in
// a directory, and gengotypes emits DigestRef into internal/lane alongside the
// wire types. The file boundary marks the api layer (ADR-047).

package lane

import "github.com/istr/strike/specs/spec"

// DigestRef is a content-addressed digest with explicit algorithm and hex
// fields. The structured form lets internal code build and inspect a digest
// without re-parsing the wire string, and ban or require specific hash functions
// at the parse boundary. The hex body reuses #Sha256 so the 64-hex grammar is
// single-sourced (scalars.cue).
#DigestRef: {
	@go(DigestRef)
	algorithm: string       @go(Algorithm)
	hex:       spec.#Sha256 @go(Hex)
}
