package registry_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
)

func TestSpecHashDeterministic(t *testing.T) {
	step := &lane.Step{
		ID:    "build",
		Image: primitive.ImageRefPtr("golang@sha256:abc"),
		Args:  []string{"build", "-o", "/out/bin"},
		Env:   map[string]string{"CGO_ENABLED": "0"},
	}
	inputHashes := map[string]primitive.Digest{"src": primitive.DigestFromHex("deadbeef00000000000000000000000000000000000000000000000000000000")}
	sourceHashes := map[string]primitive.Digest{"/src": primitive.DigestFromHex("cafebabe00000000000000000000000000000000000000000000000000000000")}

	h1 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), inputHashes, sourceHashes)
	h2 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), inputHashes, sourceHashes)
	if h1 != h2 {
		t.Fatalf("not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1.String(), "sha256:") {
		t.Fatalf("expected sha256 digest, got %q", h1)
	}
}

func TestSpecHashChangesOnInput(t *testing.T) {
	step := &lane.Step{
		ID:    "build",
		Image: primitive.ImageRefPtr("golang@sha256:abc"),
		Args:  []string{"build"},
		Env:   map[string]string{},
	}

	h1 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000011"), map[string]primitive.Digest{}, map[string]primitive.Digest{})
	h2 := registry.SpecHash(step, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000022"), map[string]primitive.Digest{}, map[string]primitive.Digest{})
	if h1 == h2 {
		t.Fatal("different images should produce different hashes")
	}
}

func TestSpecHashPreservesArgOrder(t *testing.T) {
	step1 := &lane.Step{
		ID:   "build",
		Args: []string{"build", "-o", "/out"},
		Env:  map[string]string{},
	}
	step2 := &lane.Step{
		ID:   "build",
		Args: []string{"-o", "/out", "build"},
		Env:  map[string]string{},
	}
	h1 := registry.SpecHash(step1, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), nil, nil)
	h2 := registry.SpecHash(step2, primitive.DigestFromHex("0000000000000000000000000000000000000000000000000000000000000001"), nil, nil)
	if h1 == h2 {
		t.Fatal("different arg order must produce different spec hashes")
	}
}
