package registry_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

func TestSpecHashDeterministic(t *testing.T) {
	step := &lane.Step{
		Name:  "build",
		Image: "golang@sha256:abc",
		Args:  []string{"build", "-o", "/out/bin"},
		Env:   map[string]string{"CGO_ENABLED": "0"},
	}
	inputHashes := map[string]lane.Digest{"src": "sha256:deadbeef"}
	sourceHashes := map[string]lane.Digest{"/src": "sha256:cafebabe"}

	h1 := registry.SpecHash(step, "sha256:img", inputHashes, sourceHashes)
	h2 := registry.SpecHash(step, "sha256:img", inputHashes, sourceHashes)
	if h1 != h2 {
		t.Fatalf("not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(string(h1), "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", h1)
	}
}

func TestSpecHashChangesOnInput(t *testing.T) {
	step := &lane.Step{
		Name:  "build",
		Image: "golang@sha256:abc",
		Args:  []string{"build"},
		Env:   map[string]string{},
	}

	h1 := registry.SpecHash(step, "sha256:img1", map[string]lane.Digest{}, map[string]lane.Digest{})
	h2 := registry.SpecHash(step, "sha256:img2", map[string]lane.Digest{}, map[string]lane.Digest{})
	if h1 == h2 {
		t.Fatal("different images should produce different hashes")
	}
}

func TestSpecHashPreservesArgOrder(t *testing.T) {
	step1 := &lane.Step{
		Name: "build",
		Args: []string{"build", "-o", "/out"},
		Env:  map[string]string{},
	}
	step2 := &lane.Step{
		Name: "build",
		Args: []string{"-o", "/out", "build"},
		Env:  map[string]string{},
	}
	h1 := registry.SpecHash(step1, "sha256:img", nil, nil)
	h2 := registry.SpecHash(step2, "sha256:img", nil, nil)
	if h1 == h2 {
		t.Fatal("different arg order must produce different spec hashes")
	}
}

func TestHashPathMachineIndependent(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	for _, d := range []string{dir1, dir2} {
		if err := os.MkdirAll(filepath.Join(d, "src"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(d, "src", "main.go"),
			[]byte("package main"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}

	root1, err := os.OpenRoot(dir1)
	if err != nil {
		t.Fatal(err)
	}
	defer root1.Close() //nolint:errcheck // os.Root.Close on read-only temp dir; error is not actionable

	root2, err := os.OpenRoot(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer root2.Close() //nolint:errcheck // os.Root.Close on read-only temp dir; error is not actionable

	h1, err := registry.HashPath(root1, dir1, "src")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := registry.HashPath(root2, dir2, "src")
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("same content in different dirs produced different hashes: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(string(h1), "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", h1)
	}
}

// fakeEngine is a minimal Engine mock for cache lookup tests.
type fakeEngine struct {
	container.Engine
	existsLocal bool
}

func (f *fakeEngine) ImageExists(_ context.Context, _ string) (bool, error) {
	return f.existsLocal, nil
}

// --------------------------------------------------------------------------.
// Tag.
// --------------------------------------------------------------------------.

func TestTag(t *testing.T) {
	tests := []struct {
		registry string
		step     string
		hash     lane.Digest
		want     string
		name     string
	}{
		{"ghcr.io/cache", "build", "sha256:abcdef0123456789abcdef0123456789", "ghcr.io/cache:build-abcdef0123456789", "full hash"},
		{"r.io/c", "pack", "sha256:0123", "r.io/c:pack-0123", "short hash"},
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
// HashFile and HashFileAbs.
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
	defer root.Close() //nolint:errcheck // os.Root.Close on read-only temp dir; error is not actionable

	h, err := registry.HashFile(root, "test.txt")
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if !strings.HasPrefix(string(h), "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", h)
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

func TestHashFileAbs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("test file content")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := registry.HashFileAbs(path)
	if err != nil {
		t.Fatalf("HashFileAbs: %v", err)
	}
	if !strings.HasPrefix(string(h), "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", h)
	}

	// Should match HashFile for same content.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // os.Root.Close on read-only temp dir; error is not actionable

	h2, err := registry.HashFile(root, "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if h != h2 {
		t.Fatalf("HashFileAbs and HashFile differ: %q vs %q", h, h2)
	}
}

func TestHashFileAbs_Nonexistent(t *testing.T) {
	_, err := registry.HashFileAbs("/nonexistent/path/file.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// --------------------------------------------------------------------------.
// Lookup.
// --------------------------------------------------------------------------.

func TestLookupMiss(t *testing.T) {
	client := &registry.Client{Engine: &fakeEngine{existsLocal: false}}

	found := registry.Lookup(
		context.Background(), client,
		"localhost:5555/nonexistent:tag-abc",
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
	)
	if found {
		t.Fatal("expected cache miss for nonexistent registry")
	}
}
