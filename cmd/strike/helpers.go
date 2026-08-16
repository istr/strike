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
