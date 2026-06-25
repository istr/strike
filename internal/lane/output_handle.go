package lane

import (
	"fmt"
	"strings"
)

// OutputHandle is the Go-side discriminated union for a resolved step output
// (CUE #OutputHandle, @go(-) so the generator skips the union). A step output
// is either an image output (ImageOutputHandle, whose whole rootfs is the
// artifact) or a file/directory output (FileOutputHandle, a single image layer
// selected by its diff_id). Parallel to ArtifactSource. The variant structs are
// generated; this file adds the interface and the shared behaviour to them.
type OutputHandle interface {
	// ImageRef is the digest-pinned local reference, common to both variants.
	ImageRef() string
	// HandleKind returns the discriminator: "image" or "file".
	HandleKind() string
}

// Compile-time checks: both variants implement OutputHandle.
var (
	_ OutputHandle = ImageOutputHandle{}
	_ OutputHandle = FileOutputHandle{}
)

// ImageRef implements OutputHandle.
func (h ImageOutputHandle) ImageRef() string { return h.Ref }

// HandleKind implements OutputHandle.
func (ImageOutputHandle) HandleKind() string { return "image" }

// ImageRef implements OutputHandle.
func (h FileOutputHandle) ImageRef() string { return h.Ref }

// HandleKind implements OutputHandle.
func (FileOutputHandle) HandleKind() string { return "file" }

// ManifestDigest extracts the manifest digest from a handle's imageRef.
// imageRef has the form "repo@algorithm:hex"; the digest is everything after
// the "@".
func ManifestDigest(h OutputHandle) (DigestRef, error) {
	_, d, ok := strings.Cut(h.ImageRef(), "@")
	if !ok {
		return DigestRef{}, fmt.Errorf("output handle: no digest in image ref %q", h.ImageRef())
	}
	return ParseDigest(d)
}
