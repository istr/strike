package integration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

func TestPackPipeline(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// 1. Build the Go binary in a container.
	bin := buildTestBinary(t, engine)

	// 2. Pack: assemble OCI image.
	result := packTestImage(t, engine, bin)

	t.Logf("image digest: %s", result.Digest)

	// 3. Verify digest format.
	if !strings.HasPrefix(result.Digest.String(), "sha256:") {
		t.Errorf("unexpected digest: %s", result.Digest)
	}

	// 4. Load into local store.
	regClient := &registry.Client{Engine: engine}
	digest, err := loadOCITar(ctx, regClient, result.LayoutTar)
	if err != nil {
		t.Fatalf("load OCI tar: %v", err)
	}
	t.Logf("loaded as: %s", digest)

	// 5. Inspect the loaded image via its local tag.
	localTag := "localhost/strike:" + string(digest.Hex()[:12])
	imgInfo, err := engine.ImageInspect(ctx, localTag)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if imgInfo.Size == 0 {
		t.Error("loaded image has zero size")
	}
	if imgInfo.Digest != digest {
		t.Errorf("digest mismatch: inspect=%s, load=%s", imgInfo.Digest, digest)
	}

	// 6. Verify determinism: pack again, same digest.
	result2 := packTestImage(t, engine, bin)
	if result.Digest != result2.Digest {
		t.Errorf("non-deterministic pack:\n  run 1: %s\n  run 2: %s",
			result.Digest, result2.Digest)
	}
}
