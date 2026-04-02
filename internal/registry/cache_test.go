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
	inputHashes := map[string]string{"src": "sha256:deadbeef"}
	sourceHashes := map[string]string{"/src": "sha256:cafebabe"}

	h1 := registry.SpecHash(step, "sha256:img", inputHashes, sourceHashes)
	h2 := registry.SpecHash(step, "sha256:img", inputHashes, sourceHashes)
	if h1 != h2 {
		t.Fatalf("not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
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

	h1 := registry.SpecHash(step, "sha256:img1", map[string]string{}, map[string]string{})
	h2 := registry.SpecHash(step, "sha256:img2", map[string]string{}, map[string]string{})
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
	defer root1.Close() //nolint:errcheck // test cleanup

	root2, err := os.OpenRoot(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer root2.Close() //nolint:errcheck // test cleanup

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
	if !strings.HasPrefix(h1, "sha256:") {
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
