package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry"
)

// --------------------------------------------------------------------------.
// sanitizeForLog
// --------------------------------------------------------------------------.

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"printable", "hello-world", "hello-world"},
		{"empty", "", ""},
		{"newline", "a\nb", "a_b"},
		{"tab", "a\tb", "a_b"},
		{"null", "a\x00b", "a_b"},
		{"del", "a\x7fb", "a_b"},
		{"mixed_control", "\x01\x1f\x7f", "___"},
		{"unicode", "héllo世界", "héllo世界"},
		{"space_kept", "a b", "a b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForLog(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------.
// sanitize
// --------------------------------------------------------------------------.

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase", "abc", "abc"},
		{"digits", "123", "123"},
		{"dash", "a-b", "a-b"},
		{"uppercase", "ABC", "---"},
		{"special", "a.b/c", "a-b-c"},
		{"empty", "", ""},
		{"mixed", "step-1_ok", "step-1-ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitize(tt.in)
			if got != tt.want {
				t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------.
// cachedOutputDir
// --------------------------------------------------------------------------.

func TestCachedOutputDir(t *testing.T) {
	got := cachedOutputDir("my-tag")
	if !strings.HasPrefix(got, "/tmp/strike-cache/") {
		t.Errorf("expected /tmp/strike-cache/ prefix, got %q", got)
	}
	if !strings.HasSuffix(got, "my-tag") {
		t.Errorf("expected suffix 'my-tag', got %q", got)
	}

	// Deterministic.
	a := cachedOutputDir("x")
	b := cachedOutputDir("x")
	if a != b {
		t.Error("expected deterministic output")
	}
}

// --------------------------------------------------------------------------.
// writeToOutputDir
// --------------------------------------------------------------------------.

func TestWriteToOutputDir(t *testing.T) {
	dir := t.TempDir()
	data := []byte("test-content")
	if err := writeToOutputDir(dir, "out.txt", data); err != nil {
		t.Fatalf("writeToOutputDir: %v", err)
	}

	outPath := filepath.Join(dir, "out.txt")
	got, err := os.ReadFile(outPath) //nolint:gosec // G304: test reads back from known temp dir
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "test-content" {
		t.Errorf("content = %q, want test-content", got)
	}
}

func TestWriteToOutputDir_BadDir(t *testing.T) {
	err := writeToOutputDir("/nonexistent-dir-abc123", "file", []byte("x"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

// --------------------------------------------------------------------------.
// resolveDigest
// --------------------------------------------------------------------------.

func TestResolveDigest_WithAtSign(t *testing.T) {
	// When ref contains @, the digest is extracted directly.
	digest, err := resolveDigest(context.Background(), nil, "docker.io/lib/img@sha256:abc123")
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "sha256:abc123" {
		t.Errorf("digest = %q, want sha256:abc123", digest.String())
	}
}

func TestResolveDigest_ViaInspect(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{Digest: "sha256:fromengine"},
	}
	client := &registry.Client{Engine: eng}

	digest, err := resolveDigest(context.Background(), client, "myimage:latest")
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "sha256:fromengine" {
		t.Errorf("digest = %q, want sha256:fromengine", digest.String())
	}
}

func TestResolveDigest_InspectError(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{},
	}
	client := &registry.Client{Engine: eng}

	_, err := resolveDigest(context.Background(), client, "myimage:latest")
	if err == nil {
		t.Fatal("expected error when inspect returns no digest")
	}
}
