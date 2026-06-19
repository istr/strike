// Internal artifact-handover API.
//
// This file carries layer-2 internal-API types -- the typed handoff between
// strike's pipeline phases (executor, lane state, deploy) -- kept separate
// from the layer-1 wire format in lane.cue. The two layers are distinct on
// purpose: the wire format is what an operator authors and is validated
// against CUE at parse time, while the internal API carries runtime
// properties (content-addressed digests) that cannot exist at authoring time.
// See ADR-004 (CUE as single source of truth) and ADR-046 (wire vs internal
// API).
//
// Same `package lane` as lane.cue: CUE merges same-package files in a
// directory automatically, and `cue exp gengotypes ./specs:lane` generates
// these types into internal/lane alongside the wire types. The file boundary
// is the separation; package promotion and machine-enforced direction can
// follow later without moving content.

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
