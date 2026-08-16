package registry_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"path"
	"testing"

	"github.com/istr/strike/internal/registry"
)

// packTarEntries reads a canonical pack tar and returns its headers keyed by
// cleaned entry name.
func packTarEntries(t *testing.T, data []byte) map[string]*tar.Header {
	t.Helper()
	out := make(map[string]*tar.Header)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("read pack tar: %v", err)
		}
		out[path.Clean(hdr.Name)] = hdr
	}
}

func TestPackTarFromImage_AddsImpliedDirs(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "out/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "out/a/b/c.txt", Mode: 0o644},
	}, map[string][]byte{"out/a/b/c.txt": []byte("c")})
	imgTar, diffID := buildSingleLayerImageTar(t, layerTar)

	packTar, err := registry.PackTarFromImage(imgTar, diffID, "out", "opt/app", 0o755)
	if err != nil {
		t.Fatalf("PackTarFromImage: %v", err)
	}
	entries := packTarEntries(t, packTar)

	for _, dir := range []string{"opt", "opt/app", "opt/app/a", "opt/app/a/b"} {
		hdr, ok := entries[dir]
		if !ok {
			t.Errorf("implied directory %q missing", dir)
			continue
		}
		if hdr.Typeflag != tar.TypeDir {
			t.Errorf("%q typeflag = %d, want directory", dir, hdr.Typeflag)
		}
	}
	hdr, ok := entries["opt/app/a/b/c.txt"]
	if !ok {
		t.Fatal("regular file opt/app/a/b/c.txt missing")
	}
	if hdr.Typeflag != tar.TypeReg {
		t.Errorf("opt/app/a/b/c.txt typeflag = %d, want regular file", hdr.Typeflag)
	}
}

func TestPackTarFromImage_AppliesFileModeToSingleFile(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "bin", Mode: 0o644},
	}, map[string][]byte{"bin": []byte("binary")})
	imgTar, diffID := buildSingleLayerImageTar(t, layerTar)

	packTar, err := registry.PackTarFromImage(imgTar, diffID, "bin", "app", 0o755)
	if err != nil {
		t.Fatalf("PackTarFromImage: %v", err)
	}
	entries := packTarEntries(t, packTar)

	hdr, ok := entries["app"]
	if !ok {
		t.Fatal("destination entry app missing")
	}
	if hdr.Mode != 0o755 {
		t.Errorf("app mode = %#o, want %#o", hdr.Mode, 0o755)
	}
}

func TestPackTarFromImage_KeepsProducerModesInDirectoryTree(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "out/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "out/tool.sh", Mode: 0o700},
		{Typeflag: tar.TypeReg, Name: "out/data.txt", Mode: 0o600},
	}, map[string][]byte{"out/tool.sh": []byte("tool"), "out/data.txt": []byte("data")})
	imgTar, diffID := buildSingleLayerImageTar(t, layerTar)

	packTar, err := registry.PackTarFromImage(imgTar, diffID, "out", "opt", 0o755)
	if err != nil {
		t.Fatalf("PackTarFromImage: %v", err)
	}
	entries := packTarEntries(t, packTar)

	for name, want := range map[string]int64{
		"opt/tool.sh":  0o700,
		"opt/data.txt": 0o600,
	} {
		hdr, ok := entries[name]
		if !ok {
			t.Errorf("entry %q missing", name)
			continue
		}
		if hdr.Mode != want {
			t.Errorf("%s mode = %#o, want %#o", name, hdr.Mode, want)
		}
	}
}

func TestWriteCanonicalTar_RejectsNonLocalName(t *testing.T) {
	if _, err := registry.WriteCanonicalTarNamesForTest([]string{"../escape"}); err == nil {
		t.Error("expected an error for a non-local entry name")
	}
	if _, err := registry.WriteCanonicalTarNamesForTest([]string{"local/dir"}); err != nil {
		t.Errorf("local entry name rejected: %v", err)
	}
}
