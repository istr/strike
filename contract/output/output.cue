// Resolved runtime references to a step's outputs (ADR-046, layer 2). A
// concept-tier value family carried in lane State for consumer resolution.
// imageRef (common to both variants) is the digest-pinned local reference
// (repo@sha256:<manifestDigest>) produced by the normalize round-trip through
// ggcr.
package output

import "github.com/istr/strike/contract/primitive"

#Handle: #ImageHandle | #FileHandle @go(-)

// #ImageHandle is an image output: the whole rootfs is the artifact, so there
// is no per-output layer.
#ImageHandle: {
	@go(ImageHandle)
	imageRef: string @go(Ref)

	// configDigest is the OCI image-config blob digest of the produced image:
	// the round-trip-stable content anchor. A container engine re-encodes layer
	// blobs on export, so the manifest digest imageRef carries does not survive
	// the round trip, while the config blob does (ADR-046). The config commits
	// to rootfs.diff_ids and those commit to the uncompressed layer content, so
	// this one value is enough to check an engine export against the bytes the
	// control plane produced. The deploy path performs that check before it
	// signs or pushes (ADR-051 D4).
	configDigest: primitive.#Digest @go(ConfigDigest)
}

// #FileHandle is a file or directory output: a single layer of the image,
// selected by its diff_id.
#FileHandle: {
	@go(FileHandle)
	imageRef: string @go(Ref)

	// outputID identifies the content layer for this output at the lane level: it
	// is the output id (ADR-046). It addresses the output across steps.
	outputID: primitive.#Identifier @go(OutputID)

	// layerDiffID is the OCI uncompressed-content digest (diff_id) of the layer
	// identified by outputID. It is the engine-level selection key: container
	// runtimes strip layer descriptor annotations and re-compress blobs across a
	// load/save round-trip, so neither the annotation nor the compressed layer
	// digest is stable; the diff_id is. Consumers select the layer by matching
	// this against the image config rootfs.diff_ids.
	layerDiffID: string @go(LayerDiffID)
}
