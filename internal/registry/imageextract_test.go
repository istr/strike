package registry_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// buildOCIImageTar builds an OCI layout tar from the given layers.
func buildOCIImageTar(t *testing.T, layers ...v1.Layer) []byte {
	t.Helper()
	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	var err error
	img, err = mutate.AppendLayers(img, layers...)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	data, tarErr := regtest.LayoutTar(img)
	if tarErr != nil {
		t.Fatalf("LayoutTar: %v", tarErr)
	}
	return data
}

// buildSingleLayerImageTar builds an OCI layout tar with one layer from raw tar bytes.
func buildSingleLayerImageTar(t *testing.T, layerTarBytes []byte) []byte {
	t.Helper()
	return buildOCIImageTar(t, layerFromTar(t, layerTarBytes))
}

// readFileFromDir reads a file via os.Root to avoid gosec G304.
func readFileFromDir(t *testing.T, dir, name string) ([]byte, error) {
	t.Helper()
	root, rootErr := os.OpenRoot(dir)
	if rootErr != nil {
		return nil, rootErr
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Logf("close root: %v", err)
		}
	}()
	f, openErr := root.Open(name)
	if openErr != nil {
		return nil, openErr
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Logf("close file: %v", err)
		}
	}()
	return io.ReadAll(f)
}

func TestExtractSingleLayer_File(t *testing.T) {
	content := []byte("hello world")
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "hello.txt", Mode: 0o644},
	}, map[string][]byte{"hello.txt": content})

	imgTar := buildSingleLayerImageTar(t, layerTar)
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err != nil {
		t.Fatal(err)
	}

	got, err := readFileFromDir(t, dest, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestExtractSingleLayer_Directory(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "subdir/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "subdir/a.txt", Mode: 0o644},
		{Typeflag: tar.TypeReg, Name: "subdir/b.txt", Mode: 0o644},
	}, map[string][]byte{
		"subdir/a.txt": []byte("aaa"),
		"subdir/b.txt": []byte("bbb"),
	})

	imgTar := buildSingleLayerImageTar(t, layerTar)
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"subdir/a.txt", "subdir/b.txt"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestExtractSingleLayer_RejectsMultiLayer(t *testing.T) {
	l1Tar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "a.txt", Mode: 0o644},
	}, map[string][]byte{"a.txt": []byte("a")})
	l2Tar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "b.txt", Mode: 0o644},
	}, map[string][]byte{"b.txt": []byte("b")})

	imgTar := buildOCIImageTar(t, layerFromTar(t, l1Tar), layerFromTar(t, l2Tar))
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err == nil {
		t.Fatal("expected error for multi-layer image")
	}
}

func TestExtractSingleLayer_RejectsPathTraversal(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "../escape", Mode: 0o644},
	}, map[string][]byte{"../escape": []byte("bad")})

	imgTar := buildSingleLayerImageTar(t, layerTar)
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestExtractSingleLayer_RejectsAbsolutePaths(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "/etc/passwd", Mode: 0o644},
	}, map[string][]byte{"/etc/passwd": []byte("bad")})

	imgTar := buildSingleLayerImageTar(t, layerTar)
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err == nil {
		t.Fatal("expected error for absolute path")
	}
}

func TestExtractSingleLayer_PreservesSymlink(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "target.txt", Mode: 0o777},
	}, nil)

	imgTar := buildSingleLayerImageTar(t, layerTar)
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.Readlink(filepath.Join(dest, "link"))
	if err != nil {
		t.Fatalf("expected a symlink: %v", err)
	}
	if got != "target.txt" {
		t.Errorf("link target = %q, want %q", got, "target.txt")
	}
}

func TestExtractSingleLayer_PreservesContainedSymlink(t *testing.T) {
	// Build a tar with a contained symlink, wrap it via WrapArchiveAsImage,
	// then extract and verify the symlink survives.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	entries := []struct {
		hdr     tar.Header
		content []byte
	}{
		{tar.Header{Typeflag: tar.TypeDir, Name: "mydir/", Mode: 0o755}, nil},
		{tar.Header{Typeflag: tar.TypeReg, Name: "mydir/real.txt", Size: 4, Mode: 0o644}, []byte("data")},
		{tar.Header{Typeflag: tar.TypeSymlink, Name: "mydir/link.txt", Linkname: "real.txt", Mode: 0o777}, nil},
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&e.hdr); err != nil {
			t.Fatal(err)
		}
		if e.content != nil {
			if _, err := tw.Write(e.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	_, _, wrapErr := client.WrapArchiveAsImage(context.Background(), &buf, "", "", "localhost/strike/l/s:h")
	if wrapErr != nil {
		t.Fatalf("wrap: %v", wrapErr)
	}
	if len(eng.loadBodies) == 0 {
		t.Fatal("engine received no image load")
	}

	dest := filepath.Join(t.TempDir(), "out")
	if mkErr := os.MkdirAll(dest, 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}
	if exErr := registry.ExtractSingleLayer(eng.loadBodies[0], dest); exErr != nil {
		t.Fatalf("extract: %v", exErr)
	}
	got, err := os.Readlink(filepath.Join(dest, "mydir", "link.txt"))
	if err != nil {
		t.Fatalf("expected a symlink: %v", err)
	}
	if got != "real.txt" {
		t.Errorf("link target = %q, want %q", got, "real.txt")
	}
}

func TestExtractSingleLayer_RejectsDevices(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeChar, Name: "dev", Mode: 0o666},
	}, nil)

	imgTar := buildSingleLayerImageTar(t, layerTar)
	dest := t.TempDir()
	if err := registry.ExtractSingleLayer(imgTar, dest); err == nil {
		t.Fatal("expected error for device entry")
	}
}
