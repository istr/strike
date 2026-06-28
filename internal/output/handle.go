// Package output holds the concept-tier resolved-output handles (ADR-048). The
// ImageHandle and FileHandle variant structs are generated from
// contract/output/output.cue; this file adds the Handle discriminated-union
// interface, the shared behavior, and ManifestDigest.
package output

import (
	"fmt"
	"strings"

	"github.com/istr/strike/internal/primitive"
)

// Handle is the Go-side discriminated union for a resolved step output (CUE
// #Handle, @go(-) so the generator skips the union). A step output is either an
// image output (ImageHandle, whose whole rootfs is the artifact) or a
// file/directory output (FileHandle, a single image layer selected by its
// diff_id). The variant structs are generated; this file adds the interface and
// the shared behaviour to them.
type Handle interface {
	// ImageRef is the digest-pinned local reference, common to both variants.
	ImageRef() string
	// HandleKind returns the discriminator: "image" or "file".
	HandleKind() string
}

// Compile-time checks: both variants implement Handle.
var (
	_ Handle = ImageHandle{}
	_ Handle = FileHandle{}
)

// ImageRef implements Handle.
func (h ImageHandle) ImageRef() string { return h.Ref }

// HandleKind implements Handle.
func (ImageHandle) HandleKind() string { return "image" }

// ImageRef implements Handle.
func (h FileHandle) ImageRef() string { return h.Ref }

// HandleKind implements Handle.
func (FileHandle) HandleKind() string { return "file" }

// ManifestDigest extracts the manifest digest from a handle's imageRef.
// imageRef has the form "repo@algorithm:hex"; the digest is everything after
// the "@".
func ManifestDigest(h Handle) (primitive.Digest, error) {
	_, d, ok := strings.Cut(h.ImageRef(), "@")
	if !ok {
		return "", fmt.Errorf("output handle: no digest in image ref %q", h.ImageRef())
	}
	digest := primitive.Digest(d)
	return primitive.ParseDigest(digest)
}
