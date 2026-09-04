package main

import (
	"context"
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

func resolveDigest(ctx context.Context, client *registry.Client, imageRef primitive.ImageRef) (primitive.Digest, error) {
	// A digest-pinned reference carries its own content address.
	digest, err := imageRef.Digest()
	if err != nil {
		return "", err
	}
	if digest != "" {
		return digest, nil
	}

	// Local image without digest (e.g. bootstrap root) - resolve via engine API.
	ref := string(imageRef)
	return client.InspectDigest(ctx, ref)
}
