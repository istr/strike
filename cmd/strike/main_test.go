package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

func TestHashConsistency(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src", "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "a.go"), []byte("package a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "sub", "b.go"), []byte("package b"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // test cleanup

	h1, err := registry.HashPath(root, dir, "src")
	if err != nil {
		t.Fatalf("registry.HashPath: %v", err)
	}
	h2, err := lane.SourceDigest(root, dir, "src")
	if err != nil {
		t.Fatalf("lane.SourceDigest: %v", err)
	}

	// Both functions return typed digests in "sha256:<hex>" format.
	if h1 != h2 {
		t.Fatalf("hash mismatch:\n  registry.HashPath:  %s\n  lane.SourceDigest: %s", h1, h2)
	}
}
