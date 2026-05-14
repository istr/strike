//go:build integration

package registry_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/registry"
)

func TestExtractSingleLayer_Integration(t *testing.T) {
	engine := needsEngine(t)
	client := &registry.Client{Engine: engine}
	ctx := context.Background()

	// Create a test file to wrap.
	dir := t.TempDir()
	content := []byte("extract integration test")
	srcPath := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	tag := "localhost/strike/test-extract/step:" + randomHex(t)
	_, _, err := client.WrapFileAsImage(ctx, srcPath, tag)
	if err != nil {
		t.Fatalf("WrapFileAsImage: %v", err)
	}

	// SaveImage from the real engine.
	tarBytes, err := registry.SaveImage(ctx, engine, tag)
	if err != nil {
		t.Fatalf("SaveImage: %v", err)
	}
	if len(tarBytes) == 0 {
		t.Fatal("SaveImage returned empty tar")
	}

	// Extract and verify content.
	destDir := t.TempDir()
	if err := registry.ExtractSingleLayer(tarBytes, destDir); err != nil {
		t.Fatalf("ExtractSingleLayer: %v", err)
	}

	root, err := os.OpenRoot(destDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := root.Close(); cerr != nil {
			t.Logf("close root: %v", cerr)
		}
	}()
	f, err := root.Open("data.txt")
	if err != nil {
		t.Fatalf("extracted file not found: %v", err)
	}
	got, err := io.ReadAll(f)
	if closeErr := f.Close(); closeErr != nil {
		t.Logf("close file: %v", closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}
