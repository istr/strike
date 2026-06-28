package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/testutil"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
)

func TestSpecHashDeterministic(t *testing.T) {
	step := &lane.Step{
		ID:    "build",
		Image: lane.Ptr(primitive.ImageRef("golang@sha256:abc")),
		Args:  []string{"build", "-o", "/out/bin"},
		Env:   map[string]string{"CGO_ENABLED": "0"},
	}
	inputHashes := map[string]primitive.Digest{"src": primitive.DigestFromHex("deadbeef00000000000000000000000000000000000000000000000000000000")}
	sourceHashes := map[string]primitive.Digest{"/src": primitive.DigestFromHex("cafebabe00000000000000000000000000000000000000000000000000000000")}

	h1 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), inputHashes, sourceHashes)
	h2 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), inputHashes, sourceHashes)
	if h1 != h2 {
		t.Fatalf("not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1.String(), "sha256:") {
		t.Fatalf("expected sha256 digest, got %q", h1)
	}
}

func TestSpecHashChangesOnInput(t *testing.T) {
	step := &lane.Step{
		ID:    "build",
		Image: lane.Ptr(primitive.ImageRef("golang@sha256:abc")),
		Args:  []string{"build"},
		Env:   map[string]string{},
	}

	h1 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000011"), map[string]primitive.Digest{}, map[string]primitive.Digest{})
	h2 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000022"), map[string]primitive.Digest{}, map[string]primitive.Digest{})
	if h1 == h2 {
		t.Fatal("different images should produce different hashes")
	}
}

func TestSpecHashPreservesArgOrder(t *testing.T) {
	step1 := &lane.Step{
		ID:   "build",
		Args: []string{"build", "-o", "/out"},
		Env:  map[string]string{},
	}
	step2 := &lane.Step{
		ID:   "build",
		Args: []string{"-o", "/out", "build"},
		Env:  map[string]string{},
	}
	h1 := registry.SpecHash(step1, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), nil, nil)
	h2 := registry.SpecHash(step2, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), nil, nil)
	if h1 == h2 {
		t.Fatal("different arg order must produce different spec hashes")
	}
}

// --------------------------------------------------------------------------.
// Tag.
// --------------------------------------------------------------------------.

func TestTag(t *testing.T) {
	tests := []struct {
		registry string
		step     string
		hash     primitive.Digest
		want     string
		name     string
	}{
		{"ghcr.io/cache", "build", primitive.DigestFromHex("abcdef0123456789abcdef012345678900000000000000000000000000000000"), "ghcr.io/cache:build-abcdef0123456789", "full hash"},
		{"r.io/c", "pack", primitive.DigestFromHex("0123000000000000000000000000000000000000000000000000000000000000"), "r.io/c:pack-0123000000000000", "padded hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := registry.Tag(tt.registry, tt.step, tt.hash)
			if got != tt.want {
				t.Errorf("Tag() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------.
// HashFile.
// --------------------------------------------------------------------------.

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test file content")
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.CloseLog(t, root, "cache test root")

	h, err := registry.HashFile(root, "test.txt")
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if !strings.HasPrefix(h.String(), "sha256:") {
		t.Fatalf("expected sha256 digest, got %q", h)
	}

	// Same content should produce same hash.
	h2, err := registry.HashFile(root, "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if h != h2 {
		t.Fatalf("same file, different hashes: %q vs %q", h, h2)
	}
}

func TestHashFile_Deterministic(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test file content")
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)

	h1, err := registry.HashFile(root, "test.txt")
	if err != nil {
		t.Fatalf("HashFile (1): %v", err)
	}
	if !strings.HasPrefix(h1.String(), "sha256:") {
		t.Fatalf("expected sha256 digest, got %q", h1)
	}

	// Re-open root for second hash -- same result.
	root2 := mustOpenRoot(t, dir)
	h2, err := registry.HashFile(root2, "test.txt")
	if err != nil {
		t.Fatalf("HashFile (2): %v", err)
	}
	if h1 != h2 {
		t.Fatalf("same file, different hashes: %q vs %q", h1, h2)
	}
}

func TestHashFileOutputUnchanged(t *testing.T) {
	dir := t.TempDir()
	mustWriteContent(t, filepath.Join(dir, "file.txt"), "content")

	root := mustOpenRoot(t, dir)

	h, err := registry.HashFile(root, "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.String(), "sha256:") {
		t.Fatalf("HashFile digest = %q", h)
	}
}

func mustOpenRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close root: %v", err)
		}
	})
	return root
}

func mustWriteContent(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHashFile_Nonexistent(t *testing.T) {
	root := mustOpenRoot(t, t.TempDir())
	_, err := registry.HashFile(root, "nonexistent.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
