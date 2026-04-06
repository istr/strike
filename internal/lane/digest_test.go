package lane_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func openTestRoot(t *testing.T, dir string) *os.Root {
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

func TestSourceDigestFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "hello.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, tmp)

	d1, err := lane.SourceDigest(root, tmp, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(d1), "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", d1)
	}

	// Same content -> same digest
	d2, err := lane.SourceDigest(root, tmp, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("same file, different digest: %q vs %q", d1, d2)
	}

	// Different content -> different digest
	if writeErr := os.WriteFile(path, []byte("different"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	d3, err := lane.SourceDigest(root, tmp, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("different content should produce different digest")
	}
}

func TestSourceDigestDir(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "b.go"), []byte("package sub"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, tmp)

	d1, err := lane.SourceDigest(root, tmp, "src")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(d1), "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", d1)
	}

	// Same content -> same digest (deterministic)
	d2, err := lane.SourceDigest(root, tmp, "src")
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("same directory should produce same digest")
	}

	// Change a file -> different digest
	if writeErr := os.WriteFile(filepath.Join(srcDir, "sub", "b.go"), []byte("package changed"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	d3, err := lane.SourceDigest(root, tmp, "src")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("changed file should change directory digest")
	}
}

func TestSourceDigestRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, dir)

	// Valid path succeeds
	if _, err := lane.SourceDigest(root, dir, "ok.txt"); err != nil {
		t.Fatalf("valid path failed: %v", err)
	}

	// Traversal path fails
	if _, err := lane.SourceDigest(root, dir, "../../../etc/passwd"); err == nil {
		t.Fatal("expected error for traversal path")
	}
}
