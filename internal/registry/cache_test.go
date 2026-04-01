package registry

import (
	"context"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

func TestCacheTag(t *testing.T) {
	c := &RegistryCache{Registry: "ghcr.io/istr"}

	tag := c.CacheTag("sha256:abcdef1234567890abcdef")
	want := "ghcr.io/istr/strike-cache:cache-abcdef123456"
	if tag != want {
		t.Errorf("CacheTag = %q, want %q", tag, want)
	}
}

func TestCacheTagShortKey(t *testing.T) {
	c := &RegistryCache{Registry: "ghcr.io/istr"}

	tag := c.CacheTag("sha256:abc")
	want := "ghcr.io/istr/strike-cache:cache-abc"
	if tag != want {
		t.Errorf("CacheTag = %q, want %q", tag, want)
	}
}

func TestCacheLookupMiss(t *testing.T) {
	c := &RegistryCache{Registry: "localhost:5555/nonexistent"}
	client := &Client{Engine: &fakeEngine{existsLocal: false}}

	_, found := c.Lookup(context.Background(), "sha256:0000000000000000000000000000000000000000000000000000000000000000", client)
	if found {
		t.Fatal("expected cache miss for nonexistent registry")
	}
}

func TestSpecHashDeterministic(t *testing.T) {
	step := &lane.Step{
		Name:  "build",
		Image: "golang@sha256:abc",
		Args:  []string{"build", "-o", "/out/bin"},
		Env:   map[string]string{"CGO_ENABLED": "0"},
	}
	inputHashes := map[string]string{"src": "deadbeef"}
	sourceHashes := map[string]string{"/src": "cafebabe"}

	h1 := SpecHash(step, "sha256:img", inputHashes, sourceHashes)
	h2 := SpecHash(step, "sha256:img", inputHashes, sourceHashes)
	if h1 != h2 {
		t.Fatalf("not deterministic: %q vs %q", h1, h2)
	}
}

func TestSpecHashChangesOnInput(t *testing.T) {
	step := &lane.Step{
		Name:  "build",
		Image: "golang@sha256:abc",
		Args:  []string{"build"},
		Env:   map[string]string{},
	}

	h1 := SpecHash(step, "sha256:img1", map[string]string{}, map[string]string{})
	h2 := SpecHash(step, "sha256:img2", map[string]string{}, map[string]string{})
	if h1 == h2 {
		t.Fatal("different images should produce different hashes")
	}
}

// fakeEngine is a minimal Engine mock for cache tests.
type fakeEngine struct {
	container.Engine
	existsLocal bool
}

func (f *fakeEngine) ImageExists(_ context.Context, _ string) (bool, error) {
	return f.existsLocal, nil
}
