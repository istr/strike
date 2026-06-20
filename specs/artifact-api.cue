// Internal artifact-handover API.
//
// This file carries the internal-API types: the typed handoff between strike's
// pipeline phases (executor, lane state, deploy), kept separate from the
// operator-authored wire format in lane.cue. The two are distinct on purpose.
// The wire format is what an operator authors and is validated against CUE at
// parse time; the internal API carries runtime properties (content-addressed
// digests) that cannot exist at authoring time. See
// docs/ADR-046-one-canonical-digest-pinned-image.md (wire vs internal API) and
// docs/ADR-004-cue-as-single-source-of-truth.md.
//
// Same `package lane` as lane.cue: CUE merges same-package files in a
// directory automatically, and `cue exp gengotypes ./specs:lane` generates
// these types into internal/lane alongside the wire types. The file boundary
// is the separation between the wire and internal types.

package lane

// ---------------------------------------------------------------------------
// Runtime artifact carrier
// ---------------------------------------------------------------------------

// Artifact is a content-addressed output from a step. This type flows
// between executor, lane state, and deploy -- it is the internal
// interface for artifact handover between pipeline phases.
#Artifact: {
	@go(Artifact)
	type:         #ArtifactType @go(Type)
	digest:       #Digest       @go(Digest,type=Digest)
	size:         int & >=0     @go(Size)
	contentType?: string        @go(ContentType,optional=nillable)
	metadata?: {
		[string]: string @go(Metadata)
	}
}

// OutputHandle is the resolved runtime reference to a step's output image
// (ADR-046, layer 2). Populated during execution when the producer wraps or
// commits the output; carried in State for consumer resolution. imageRef is
// the digest-pinned local reference (repo@sha256:<manifestDigest>) produced
// by the normalize round-trip through ggcr.
#OutputHandle: {
	@go(OutputHandle)
	imageRef: string @go(ImageRef)
}
