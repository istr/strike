package registry_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

func TestExtractSingleLayer_Integration(t *testing.T) {
	engine := needsEngine(t)
	ctx := context.Background()

	content := []byte("extract integration test")
	tarBytes, _, err := regtest.BuildImageTar("data.txt", content)
	if err != nil {
		t.Fatalf("BuildImageTar: %v", err)
	}

	tag := "localhost/strike/test-extract/step:" + randomHex(t)
	id, err := engine.ImageLoad(ctx, bytes.NewReader(tarBytes))
	if err != nil {
		t.Fatalf("ImageLoad: %v", err)
	}
	if tagErr := engine.ImageTag(ctx, id, tag); tagErr != nil {
		t.Fatalf("ImageTag: %v", tagErr)
	}

	saved, err := registry.SaveImage(ctx, engine, tag)
	if err != nil {
		t.Fatalf("SaveImage: %v", err)
	}
	if len(saved) == 0 {
		t.Fatal("SaveImage returned empty tar")
	}

	destDir := t.TempDir()
	if exErr := registry.ExtractSingleLayer(saved, destDir); exErr != nil {
		t.Fatalf("ExtractSingleLayer: %v", exErr)
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
