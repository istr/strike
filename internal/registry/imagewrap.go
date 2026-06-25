package registry

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/lane"
)

// ContentSizeAnnotation is the OCI annotation key that stores the logical
// content size (in bytes) of the wrapped artifact. Written by wrapOutputs,
// read by the cache-hit path to restore Artifact.Size without re-extraction.
const ContentSizeAnnotation = "dev.strike.content-size"

// OutputLayerAnnotation is the OCI layer-descriptor annotation key that carries
// the output id of a content layer. The producer stamps one layer per output
// (ADR-046); a consumer selects the layer identified by the output id
// in the handle.
const OutputLayerAnnotation = "dev.strike.output.id"

// WrapImageOutputAsImage loads an existing OCI tar into the engine's local
// store, tags it, and returns the manifest digest and the tar file size.
// The controller-computed manifest digest is verified against the engine.
// root is the output directory; name is the relative tar path within it.
// Optional extra annotations are merged into the manifest alongside the
// standard created and content-size annotations.
func (c *Client) WrapImageOutputAsImage(ctx context.Context, root *os.Root, name, tag string, extra ...map[string]string) (lane.DigestRef, int64, error) {
	info, err := root.Stat(name)
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image stat: %w", err)
	}
	size := info.Size()

	f, err := root.Open(name)
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image: %w", err)
	}
	defer closer.Warn(f, "wrap image")

	return c.wrapImageFromReader(ctx, f, size, tag, extra...)
}

// wrapImageFromReader loads an OCI-layout tar from r (size bytes), annotates
// it, loads it into the engine, tags it, and verifies the controller digest
// against the engine. Shared by WrapImageOutputAsImage (host file) and
// WrapImageArchiveAsImage (engine archive stream).
func (c *Client) wrapImageFromReader(ctx context.Context, r io.Reader, size int64, tag string, extra ...map[string]string) (lane.DigestRef, int64, error) {
	img, cleanup, err := extractMainImage(r)
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image: %w", err)
	}
	defer cleanup()

	ann := map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
		ContentSizeAnnotation:              strconv.FormatInt(size, 10),
	}
	for _, m := range extra {
		for k, v := range m {
			ann[k] = v
		}
	}
	annotated, ok := mutate.Annotations(img, ann).(v1.Image)
	if !ok {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image: annotate: unexpected type")
	}
	img = annotated

	expectedDigest, err := img.Digest()
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image digest: %w", err)
	}

	tarReader, err := singleImageTar(img, nil)
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, tarReader)
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image load: %w", err)
	}

	if tagErr := c.Engine.ImageTag(ctx, id, tag); tagErr != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image tag: %w", tagErr)
	}

	engineDigest, err := c.InspectDigest(ctx, tag)
	if err != nil {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image inspect: %w", err)
	}

	controllerDigest := v1HashToDigest(expectedDigest)
	if engineDigest != controllerDigest {
		return lane.DigestRef{}, 0, fmt.Errorf("wrap image: digest mismatch: controller=%s engine=%s", controllerDigest, engineDigest)
	}
	return engineDigest, size, nil
}

// finalizeImage stamps the reproducible-created and content-size annotations
// on an assembled image, loads it into the engine, tags it, and verifies that
// the controller-computed manifest digest matches the engine-stored digest.
// The manifest digest commits to every layer (ADR-046), so no per-layer digest
// is checked. size is the total logical content size across all layers.
func (c *Client) finalizeImage(ctx context.Context, img v1.Image, tag string, size int64) (lane.DigestRef, error) {
	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
		ContentSizeAnnotation:              strconv.FormatInt(size, 10),
	}).(v1.Image)
	if !ok {
		return lane.DigestRef{}, fmt.Errorf("annotate image: unexpected type")
	}
	img = annotated

	expectedHash, err := img.Digest()
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("compute digest: %w", err)
	}

	r, err := singleImageTar(img, nil)
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("write image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, r)
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("image load: %w", err)
	}

	if tagErr := c.Engine.ImageTag(ctx, id, tag); tagErr != nil {
		return lane.DigestRef{}, fmt.Errorf("image tag: %w", tagErr)
	}

	engineDigest, err := c.InspectDigest(ctx, tag)
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("inspect digest: %w", err)
	}

	controllerDigest := v1HashToDigest(expectedHash)
	if engineDigest != controllerDigest {
		return lane.DigestRef{}, fmt.Errorf("digest mismatch: controller=%s engine=%s", controllerDigest, engineDigest)
	}
	return engineDigest, nil
}

// OutputArchive is one step output's engine container-archive stream plus its
// re-rooting prefixes and the output id (OutputID) that identifies its layer.
// Each becomes one canonical OCI layer in the assembled step image, stamped
// with OutputID under OutputLayerAnnotation. The annotation aids OCI
// introspection but is not the selection key: runtimes strip it on load, so
// consumers select by the layer's diff_id (see WrapResult.LayerDiffIDs).
type OutputArchive struct {
	Tar         io.Reader
	StripPrefix string
	DestPrefix  string
	OutputID    string
}

// WrapResult is the outcome of assembling a step's outputs into one image.
// Digest is the manifest digest (the single integrity anchor); Size is the
// total logical content size across all layers; LayerDiffIDs maps each output
// id to its layer's uncompressed-content digest (diff_id), the engine-level
// key a consumer uses to select that layer after an engine round-trip.
type WrapResult struct {
	LayerDiffIDs map[string]string
	Digest       lane.DigestRef
	Size         int64
}

// WrapOutputsAsImage assembles every file and directory output of a step into
// one canonical, digest-pinned image -- one layer per output (ADR-046) --
// loads it, tags it, and returns the manifest digest, total content size, and
// the per-output layer diff_ids. The manifest digest is the single integrity
// anchor; it commits to every layer, so no per-layer digest is checked. Layer
// order follows the input slice.
func (c *Client) WrapOutputsAsImage(ctx context.Context, outs []OutputArchive, tag string) (WrapResult, error) {
	base := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	adds := make([]mutate.Addendum, 0, len(outs))
	diffIDs := make(map[string]string, len(outs))
	var total int64
	for _, out := range outs {
		layer, size, err := canonicalLayerFromTar(out.Tar, out.StripPrefix, out.DestPrefix)
		if err != nil {
			return WrapResult{}, fmt.Errorf("canonicalize output %q: %w", out.OutputID, err)
		}
		diffID, err := layer.DiffID()
		if err != nil {
			return WrapResult{}, fmt.Errorf("diff id output %q: %w", out.OutputID, err)
		}
		diffIDs[out.OutputID] = diffID.String()
		adds = append(adds, mutate.Addendum{
			Layer:       layer,
			Annotations: map[string]string{OutputLayerAnnotation: out.OutputID},
		})
		total += size
	}
	img, err := mutate.Append(base, adds...)
	if err != nil {
		return WrapResult{}, fmt.Errorf("assemble output layers: %w", err)
	}
	digest, err := c.finalizeImage(ctx, img, tag, total)
	if err != nil {
		return WrapResult{}, err
	}
	return WrapResult{Digest: digest, Size: total, LayerDiffIDs: diffIDs}, nil
}

// v1HashToDigest converts a go-containerregistry v1.Hash to a lane.DigestRef.
func v1HashToDigest(h v1.Hash) lane.DigestRef {
	return lane.DigestRef{Algorithm: h.Algorithm, Hex: lane.Sha256(h.Hex)}
}

// extractMainImage reads an OCI layout tar from r and returns the first
// image from the index. The returned cleanup function removes the temporary
// directory backing the layout and must be called after the image is no
// longer needed.
func extractMainImage(r io.Reader) (v1.Image, func(), error) {
	tmpDir, err := os.MkdirTemp("", "strike-wrap-load-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { closer.Remove(tmpDir, "wrap image load") }

	tmpRoot, rootErr := os.OpenRoot(tmpDir)
	if rootErr != nil {
		cleanup()
		return nil, nil, rootErr
	}
	defer closer.Warn(tmpRoot, "wrap image load root")

	if extractErr := extractTar(r, tmpRoot); extractErr != nil {
		cleanup()
		return nil, nil, fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read manifest: %w", err)
	}

	if len(manifest.Manifests) == 0 {
		cleanup()
		return nil, nil, fmt.Errorf("empty image index")
	}

	desc := manifest.Manifests[0]
	img, imgErr := idx.Image(desc.Digest)
	if imgErr != nil {
		cleanup()
		return nil, nil, imgErr
	}
	return img, cleanup, nil
}
