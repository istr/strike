package registry_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

// stubSaveEngine implements container.Engine with only ImageSave functional.
type stubSaveEngine struct {
	container.Engine // embed to satisfy interface
	err              error
	data             []byte
}

func (e *stubSaveEngine) ImageSave(_ context.Context, _ string) (io.ReadCloser, error) {
	if e.err != nil {
		return nil, e.err
	}
	return io.NopCloser(bytes.NewReader(e.data)), nil
}

func TestSaveImage_ReturnsTarBytes(t *testing.T) {
	want := []byte("oci-tar-bytes")
	eng := &stubSaveEngine{data: want}
	got, err := registry.SaveImage(context.Background(), eng, "test:tag")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSaveImage_PropagatesError(t *testing.T) {
	eng := &stubSaveEngine{err: fmt.Errorf("engine down")}
	_, err := registry.SaveImage(context.Background(), eng, "test:tag")
	if err == nil {
		t.Fatal("expected error")
	}
}

// buildLayerTar creates a tar archive with the given entries.
func buildLayerTar(t *testing.T, entries []tar.Header, contents map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, hdr := range entries {
		h := hdr
		if c, ok := contents[h.Name]; ok {
			h.Size = int64(len(c))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("write header %s: %v", h.Name, err)
		}
		if c, ok := contents[h.Name]; ok {
			if _, err := tw.Write(c); err != nil {
				t.Fatalf("write content %s: %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// layerFromTar creates a v1.Layer from raw layer tar bytes.
func layerFromTar(t *testing.T, data []byte) v1.Layer {
	t.Helper()
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	layer, err := tarball.LayerFromOpener(opener)
	if err != nil {
		t.Fatalf("LayerFromOpener: %v", err)
	}
	return layer
}

// buildLayeredImageTar builds an OCI layout tar whose content layers carry the
// given raw layer tars, keyed by output id. It returns the layout tar and a
// map from each output id to that layer's uncompressed-content digest
// (diff_id) -- the stable engine-level selection key (ADR-046) a consumer
// passes to SeedTarFromImage. Layer order follows the sorted
// output ids for determinism.
func buildLayeredImageTar(t *testing.T, layers map[string][]byte) ([]byte, map[string]string) {
	t.Helper()
	ids := make([]string, 0, len(layers))
	for id := range layers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	diffIDs := make(map[string]string, len(ids))
	for _, id := range ids {
		layer := layerFromTar(t, layers[id])
		diffID, diffErr := layer.DiffID()
		if diffErr != nil {
			t.Fatalf("DiffID %s: %v", id, diffErr)
		}
		diffIDs[id] = diffID.String()
		var err error
		img, err = mutate.Append(img, mutate.Addendum{
			Layer:       layer,
			Annotations: map[string]string{registry.OutputLayerAnnotation: id},
		})
		if err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}
	data, tarErr := regtest.LayoutTar(img)
	if tarErr != nil {
		t.Fatalf("LayoutTar: %v", tarErr)
	}
	return data, diffIDs
}

// buildSingleLayerImageTar builds an OCI layout tar with one content layer
// (from raw tar bytes) and returns the tar plus that layer's diff_id, which
// the consumer passes as the selection key.
func buildSingleLayerImageTar(t *testing.T, layerTarBytes []byte) ([]byte, string) {
	t.Helper()
	const id = "content"
	data, diffIDs := buildLayeredImageTar(t, map[string][]byte{id: layerTarBytes})
	return data, diffIDs[id]
}
