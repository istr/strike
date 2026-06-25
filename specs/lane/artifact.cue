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
// directory automatically, and `cue exp gengotypes ./specs/lane` generates
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
	digest:       #Digest       @go(Digest)
	size:         int & >=0     @go(Size)
	contentType?: string        @go(ContentType,optional=nillable)
	metadata?: {
		[string]: string @go(Metadata)
	}
}

// OutputHandle is the resolved runtime reference to a step's output (ADR-046,
// layer 2), discriminated by output kind. It is carried in State for consumer
// resolution. imageRef (common to both variants) is the digest-pinned local
// reference (repo@sha256:<manifestDigest>) produced by the normalize
// round-trip through ggcr. @go(-): hand-modelled as a Go interface over the two
// variant structs in internal/lane/output_handle.go, parallel to
// #ArtifactSource. The variant structs below are generated; the union is not.
#OutputHandle: #ImageOutputHandle | #FileOutputHandle @go(-)

// #ImageOutputHandle is an image output: the whole rootfs is the artifact, so
// there is no per-output layer.
#ImageOutputHandle: {
	@go(ImageOutputHandle)
	imageRef: string @go(Ref)
}

// #FileOutputHandle is a file or directory output: a single layer of the
// image, selected by its diff_id.
#FileOutputHandle: {
	@go(FileOutputHandle)
	imageRef: string @go(Ref)

	// outputID identifies the content layer for this output at the lane level: it
	// is the output id (ADR-046). It addresses the output across steps.
	outputID: #Identifier @go(OutputID)

	// layerDiffID is the OCI uncompressed-content digest (diff_id) of the layer
	// identified by outputID. It is the engine-level selection key: container
	// runtimes strip layer descriptor annotations and re-compress blobs across a
	// load/save round-trip, so neither the annotation nor the compressed layer
	// digest is stable; the diff_id is. Consumers select the layer by matching
	// this against the image config rootfs.diff_ids.
	layerDiffID: string @go(LayerDiffID)
}
