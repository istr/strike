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

// SignedAnnotation is the OCI annotation key that records whether a pack
// step signed this artifact. Written by executePack, read by the cache-hit
// path to restore Artifact.Signed without re-inspection.
const SignedAnnotation = "dev.strike.signed"

// WrapImageOutputAsImage loads an existing OCI tar into the engine's local
// store, tags it, and returns the manifest digest and the tar file size.
// The controller-computed manifest digest is verified against the engine.
// root is the output directory; name is the relative tar path within it.
// Optional extra annotations are merged into the manifest alongside the
// standard created and content-size annotations.
func (c *Client) WrapImageOutputAsImage(ctx context.Context, root *os.Root, name, tag string, extra ...map[string]string) (lane.Digest, int64, error) {
	info, err := root.Stat(name)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image stat: %w", err)
	}
	size := info.Size()

	f, err := root.Open(name)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: %w", err)
	}
	defer closer.Warn(f, "wrap image")

	return c.wrapImageFromReader(ctx, f, size, tag, extra...)
}

// wrapImageFromReader loads an OCI-layout tar from r (size bytes), annotates
// it, loads it into the engine, tags it, and verifies the controller digest
// against the engine. Shared by WrapImageOutputAsImage (host file) and
// WrapImageArchiveAsImage (engine archive stream).
func (c *Client) wrapImageFromReader(ctx context.Context, r io.Reader, size int64, tag string, extra ...map[string]string) (lane.Digest, int64, error) {
	img, cleanup, err := extractMainImage(r)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: %w", err)
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
		return lane.Digest{}, 0, fmt.Errorf("wrap image: annotate: unexpected type")
	}
	img = annotated

	expectedDigest, err := img.Digest()
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image digest: %w", err)
	}

	tarReader, err := singleImageTar(img, nil)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, tarReader)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image load: %w", err)
	}

	if tagErr := c.Engine.ImageTag(ctx, id, tag); tagErr != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image tag: %w", tagErr)
	}

	engineDigest, err := c.InspectDigest(ctx, tag)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image inspect: %w", err)
	}

	controllerDigest := v1HashToDigest(expectedDigest)
	if engineDigest != controllerDigest {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: digest mismatch: controller=%s engine=%s", controllerDigest, engineDigest)
	}
	return engineDigest, size, nil
}

// loadTagVerify builds a single-layer OCI image from the given layer,
// loads it into the engine, tags it, and returns the manifest digest.
// The controller-computed manifest digest is verified against the engine.
// size is the logical content size written as the dev.strike.content-size
// annotation for cache-hit restoration.
func (c *Client) loadTagVerify(ctx context.Context, layer v1.Layer, tag string, size int64) (lane.Digest, error) {
	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)

	img, err := mutate.AppendLayers(img, layer)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("append layer: %w", err)
	}

	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
		ContentSizeAnnotation:              strconv.FormatInt(size, 10),
	}).(v1.Image)
	if !ok {
		return lane.Digest{}, fmt.Errorf("annotate image: unexpected type")
	}
	img = annotated

	expectedHash, err := img.Digest()
	if err != nil {
		return lane.Digest{}, fmt.Errorf("compute digest: %w", err)
	}

	r, err := singleImageTar(img, nil)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("write image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, r)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("image load: %w", err)
	}

	if tagErr := c.Engine.ImageTag(ctx, id, tag); tagErr != nil {
		return lane.Digest{}, fmt.Errorf("image tag: %w", tagErr)
	}

	engineDigest, err := c.InspectDigest(ctx, tag)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("inspect digest: %w", err)
	}

	controllerDigest := v1HashToDigest(expectedHash)
	if engineDigest != controllerDigest {
		return lane.Digest{}, fmt.Errorf("digest mismatch: controller=%s engine=%s", controllerDigest, engineDigest)
	}
	return engineDigest, nil
}

// v1HashToDigest converts a go-containerregistry v1.Hash to a lane.Digest.
func v1HashToDigest(h v1.Hash) lane.Digest {
	return lane.Digest{Algorithm: h.Algorithm, Hex: h.Hex}
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
