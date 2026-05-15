package main

import (
	"context"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
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
// writeToOutputDir
// --------------------------------------------------------------------------.

func TestWriteToOutputDir(t *testing.T) {
	dir := t.TempDir()
	data := []byte("test-content")
	if err := writeToOutputDir(dir, "out.txt", data); err != nil {
		t.Fatalf("writeToOutputDir: %v", err)
	}

	got := testutil.ReadTemp(t, dir, "out.txt")
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
