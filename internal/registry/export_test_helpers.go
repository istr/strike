package registry

import (
	"bytes"
	"io"
	"os"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/lane"
)

// ExtractTarForTest is an exported wrapper around extractTar for use in tests.
func ExtractTarForTest(data []byte, dst string) error {
	return extractTar(bytes.NewReader(data), dst)
}

// writeTempLayerFile writes content to a temp file and returns its path.
func writeTempLayerFile(content []byte) (string, error) {
	tmp, err := os.CreateTemp("", "strike-test-layer-*")
	if err != nil {
		return "", err
	}
	if _, err = tmp.Write(content); err != nil {
		warnClose(tmp, "test layer file")
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

// BuildTestImageTar creates a single-layer OCI image tar containing the
// given file. Returns the tar bytes and the manifest digest. Exported for
// use in tests outside the registry package.
func BuildTestImageTar(fileName string, content []byte) ([]byte, lane.Digest, error) {
	tmpPath, writeErr := writeTempLayerFile(content)
	if writeErr != nil {
		return nil, lane.Digest{}, writeErr
	}
	defer warnRemoveAll(tmpPath, "test layer file")

	layer, _, layerErr := wrapFileLayer(tmpPath, "/"+fileName, 0o644)
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
// Exported for use in tests outside the registry package.
func SingleImageTarForTest(img v1.Image) ([]byte, error) {
	r, err := singleImageTar(img, nil)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
