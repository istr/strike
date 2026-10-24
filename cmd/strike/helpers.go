package main

import (
	"fmt"
	"strings"

	"github.com/istr/strike/internal/primitive"
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

// resolveDigest returns the content address a lane image reference is pinned
// to. The schema admits only digest-pinned references, so a reference without
// one is rejected rather than resolved through the engine.
func resolveDigest(imageRef primitive.ImageRef) (primitive.Digest, error) {
	digest, err := imageRef.Digest()
	if err != nil {
		return "", err
	}
	if digest == "" {
		return "", fmt.Errorf("image reference %q carries no digest", imageRef)
	}
	return digest, nil
}
