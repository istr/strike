//go:build integration

package registry_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry"
)

func needsEngine(t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	engine, err := container.New()
	if err != nil {
		t.Fatalf("no container engine: %v", err)
	}
	ctx := context.Background()
	if err := engine.Ping(ctx); err != nil {
		t.Fatalf("container engine not responding: %v", err)
	}
	return engine
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestWrapFileAsImage_Integration(t *testing.T) {
	engine := needsEngine(t)
	client := &registry.Client{Engine: engine}
	ctx := context.Background()

	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("integration test content"), 0o644); err != nil {
		t.Fatal(err)
	}

	tag := "localhost/strike/test-lane/test-step:" + randomHex(t)
	t.Cleanup(func() {
		// Best-effort cleanup: remove the image from the engine.
		info, err := engine.ImageInspect(ctx, tag)
		if err == nil && info != nil {
			// Use ImageTag to a throwaway name and let the engine GC it.
			// There's no ImageDelete in the Engine interface, so we just leave it.
			// The random tag avoids collision with future runs.
		}
	})

	digest, err := client.WrapFileAsImage(ctx, path, tag)
	if err != nil {
		t.Fatalf("WrapFileAsImage: %v", err)
	}

	if digest.Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", digest.Algorithm)
	}
	if len(digest.Hex) != 64 {
		t.Errorf("hex length = %d, want 64", len(digest.Hex))
	}

	// Verify the image exists in the engine.
	info, err := engine.ImageInspect(ctx, tag)
	if err != nil {
		t.Fatalf("ImageInspect(%s): %v", tag, err)
	}
	if !strings.HasPrefix(info.Digest, "sha256:") {
		t.Errorf("engine digest = %q, expected sha256: prefix", info.Digest)
	}
}
