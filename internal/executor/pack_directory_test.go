package executor_test

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

func TestAssembleImage_DirectoryInput(t *testing.T) {
	src := setupDirTree(t, map[string]string{
		"a.txt":        "a",
		"subdir/b.txt": "b",
	})

	spec := &lane.PackSpec{
		Base:  "scratch",
		Files: []lane.PackFile{{From: "src.tree", Dest: "/target"}},
	}
	inputPaths := map[string]string{"/target": src}

	result, err := executor.AssembleImage(empty.Image, spec, inputPaths)
	if err != nil {
		t.Fatal(err)
	}

	entries := layerEntries(t, result.Image)
	sort.Strings(entries)

	want := []string{"target/", "target/a.txt", "target/subdir/", "target/subdir/b.txt"}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry[%d] = %q, want %q", i, entries[i], want[i])
		}
	}
}

func TestAssembleImage_DirectoryInput_DeterministicDigest(t *testing.T) {
	build := func() string {
		src := setupDirTree(t, map[string]string{"sub/f.txt": "content"})
		spec := &lane.PackSpec{
			Base:  "scratch",
			Files: []lane.PackFile{{From: "s.tree", Dest: "/app"}},
		}
		result, err := executor.AssembleImage(empty.Image, spec, map[string]string{"/app": src})
		if err != nil {
			t.Fatal(err)
		}
		return result.Digest.String()
	}

	d1 := build()
	d2 := build()
	if d1 != d2 {
		t.Errorf("non-deterministic: %s != %s", d1, d2)
	}
}

func TestAssembleImage_DirectoryInput_RejectsSymlinks(t *testing.T) {
	src := t.TempDir()
	target := filepath.Join(src, "real.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(src, "link.txt")); err != nil {
		t.Fatal(err)
	}

	spec := &lane.PackSpec{
		Base:  "scratch",
		Files: []lane.PackFile{{From: "s.tree", Dest: "/out"}},
	}
	_, err := executor.AssembleImage(empty.Image, spec, map[string]string{"/out": src})
	if err == nil {
		t.Fatal("expected error for symlink in directory input")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink: %v", err)
	}
}

// setupDirTree creates a temp directory with the given file entries and
// returns the root path. Keys are relative paths; values are file content.
func setupDirTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// layerEntries extracts all tar entry names from all layers of an image.
func layerEntries(t *testing.T, img v1.Image) []string {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(rc)
		for {
			hdr, hdrErr := tr.Next()
			if hdrErr == io.EOF {
				break
			}
			if hdrErr != nil {
				t.Fatal(hdrErr)
			}
			names = append(names, hdr.Name)
		}
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return names
}
