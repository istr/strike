package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
)

// sanitizeForLog replaces control characters to prevent log injection.
func sanitizeForLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// writeToOutputDir opens an os.Root on dir, creates name, and writes data.
func writeToOutputDir(dir, name string, data []byte) (err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := root.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	f, err := root.Create(name)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(data)
	return err
}

// removeStrikeScratch deletes a per-step scratch directory.
// It guards against accidental removal of unrelated paths by
// verifying the path begins with the expected strike-tempdir
// prefix; the guard doubles as a sanitization point for
// gosec's taint analysis.
func removeStrikeScratch(outDir string) {
	expectedPrefix := filepath.Join(os.TempDir(), "strike-")
	cleaned := filepath.Clean(outDir)
	if !strings.HasPrefix(cleaned, expectedPrefix) {
		log.Printf("WARN refuse to remove non-strike path %s", sanitizeForLog(outDir))
		return
	}
	if err := os.RemoveAll(cleaned); err != nil {
		log.Printf("WARN cleanup %s: %v", sanitizeForLog(cleaned), err)
	}
}

func resolveDigest(ctx context.Context, client *registry.Client, imageRef primitive.ImageRef) (primitive.Digest, error) {
	// Image ref already contains @sha256: - extract the digest.
	s := string(imageRef)
	for i, c := range s {
		if c == '@' {
			digest := primitive.Digest(s[i+1:])
			return primitive.ParseDigest(digest)
		}
	}

	// Local image without digest (e.g. bootstrap root) - resolve via engine API.
	return client.InspectDigest(ctx, s)
}
