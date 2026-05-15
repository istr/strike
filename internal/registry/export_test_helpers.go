package registry

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/lane"
)

// ExtractTarForTest is an exported wrapper around extractTar for use in tests.
func ExtractTarForTest(data []byte, root *os.Root) error {
	return extractTar(bytes.NewReader(data), root)
}

// BuildTestImageTar creates a single-layer OCI image tar containing the
// given file. Returns the tar bytes and the manifest digest. Exported for
// use in tests outside the registry package.
func BuildTestImageTar(fileName string, content []byte) ([]byte, lane.Digest, error) {
	tmpDir, mkErr := os.MkdirTemp("", "strike-test-layer-")
	if mkErr != nil {
		return nil, lane.Digest{}, mkErr
	}
	defer closer.Remove(tmpDir, "test layer dir")

	filePath := tmpDir + "/" + fileName
	if parent := filepath.Dir(filePath); parent != tmpDir {
		if mkdErr := os.MkdirAll(parent, 0o750); mkdErr != nil {
			return nil, lane.Digest{}, mkdErr
		}
	}
	if writeErr := os.WriteFile(filePath, content, 0o600); writeErr != nil {
		return nil, lane.Digest{}, writeErr
	}
	tmpRoot, rootErr := os.OpenRoot(tmpDir)
	if rootErr != nil {
		return nil, lane.Digest{}, rootErr
	}
	defer closer.Warn(tmpRoot, "test layer root")

	layer, _, layerErr := wrapFileLayer(tmpRoot, fileName, "/"+fileName, 0o644)
	if layerErr != nil {
		return nil, lane.Digest{}, layerErr
	}

	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	img, appendErr := mutate.AppendLayers(img, layer)
	if appendErr != nil {
		return nil, lane.Digest{}, appendErr
	}

	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return nil, lane.Digest{}, appendErr
	}
	img = annotated

	h, digestErr := img.Digest()
	if digestErr != nil {
		return nil, lane.Digest{}, digestErr
	}

	r, tarErr := singleImageTar(img, nil)
	if tarErr != nil {
		return nil, lane.Digest{}, tarErr
	}

	data, readErr := io.ReadAll(r)
	if readErr != nil {
		return nil, lane.Digest{}, readErr
	}
	return data, lane.Digest{Algorithm: h.Algorithm, Hex: h.Hex}, nil
}

// SingleImageTarForTest wraps an arbitrary v1.Image into an OCI layout tar.
// If annotations are provided, the first map is set on the index descriptor.
// Exported for use in tests outside the registry package.
func SingleImageTarForTest(img v1.Image, annotations ...map[string]string) ([]byte, error) {
	var ann map[string]string
	if len(annotations) > 0 {
		ann = annotations[0]
	}
	r, err := singleImageTar(img, ann)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
