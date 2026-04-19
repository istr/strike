package main

import (
	"context"
	"os"
	"strings"

	"github.com/istr/strike/internal/lane"
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

func sanitize(s string) string {
	result := make([]byte, len(s))
	for i, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result[i] = c
		} else {
			result[i] = '-'
		}
	}
	return string(result)
}

func cachedOutputDir(tag string) string {
	// Local output mounted from container store.
	return "/tmp/strike-cache/" + sanitize(tag)
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

func resolveDigest(ctx context.Context, client *registry.Client, imageRef string) (lane.Digest, error) {
	// Image ref already contains @sha256: - extract the digest.
	for i, c := range imageRef {
		if c == '@' {
			return lane.ParseDigest(imageRef[i+1:])
		}
	}

	// Local image without digest (e.g. bootstrap root) - resolve via engine API.
	return client.InspectDigest(ctx, imageRef)
}
