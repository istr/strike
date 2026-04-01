package lane_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestSourceDigestFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "hello.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	d1, err := lane.SourceDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d1, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", d1)
	}

	// Same content -> same digest
	d2, err := lane.SourceDigest(path)
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
	d3, err := lane.SourceDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("different content should produce different digest")
	}
}

func TestSourceDigestDir(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "a.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "sub", "b.go"), []byte("package sub"), 0o600); err != nil {
		t.Fatal(err)
	}

	d1, err := lane.SourceDigest(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d1, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", d1)
	}

	// Same content -> same digest (deterministic)
	d2, err := lane.SourceDigest(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("same directory should produce same digest")
	}

	// Change a file -> different digest
	if writeErr := os.WriteFile(filepath.Join(tmp, "sub", "b.go"), []byte("package changed"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	d3, err := lane.SourceDigest(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("changed file should change directory digest")
	}
}

func TestInputDigest(t *testing.T) {
	s := lane.NewState()
	if err := s.Register("build", "binary", lane.Artifact{
		Type:   "file",
		Digest: "sha256:abc123def456",
	}); err != nil {
		t.Fatal(err)
	}

	ref := lane.InputRef{Name: "bin", From: "build.binary", Mount: "/input/bin"}
	d, err := lane.InputDigest(ref, s)
	if err != nil {
		t.Fatal(err)
	}
	if d != "sha256:abc123def456" {
		t.Fatalf("expected inherited digest, got %q", d)
	}
}

func TestInputDigestMissing(t *testing.T) {
	s := lane.NewState()
	ref := lane.InputRef{Name: "bin", From: "nonexistent.output", Mount: "/input/bin"}
	_, err := lane.InputDigest(ref, s)
	if err == nil {
		t.Fatal("expected error for missing artifact")
	}
}

func TestCacheKeyDeterministic(t *testing.T) {
	step := &lane.Step{
		Name:  "build",
		Image: "golang@sha256:abc",
		Args:  []string{"build", "-o", "/out/bin", "."},
		Env:   map[string]string{"CGO_ENABLED": "0", "GOOS": "linux"},
	}
	digests := map[string]string{
		"source:/src": "sha256:111",
	}

	k1 := lane.CacheKey(step, "sha256:imageabc", digests)
	k2 := lane.CacheKey(step, "sha256:imageabc", digests)
	if k1 != k2 {
		t.Fatalf("cache key not deterministic: %q vs %q", k1, k2)
	}
}

func TestCacheKeyChangesOnInput(t *testing.T) {
	step := &lane.Step{
		Name:  "build",
		Image: "golang@sha256:abc",
		Args:  []string{"build"},
		Env:   map[string]string{},
	}

	k1 := lane.CacheKey(step, "sha256:img1", map[string]string{"src": "sha256:aaa"})
	k2 := lane.CacheKey(step, "sha256:img1", map[string]string{"src": "sha256:bbb"})
	if k1 == k2 {
		t.Fatal("different input digests should produce different cache keys")
	}

	k3 := lane.CacheKey(step, "sha256:img2", map[string]string{"src": "sha256:aaa"})
	if k1 == k3 {
		t.Fatal("different image digest should produce different cache keys")
	}
}
