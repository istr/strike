package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

func TestPackPipeline(t *testing.T) {
	engine := needsEngine(t)
	ctx := context.Background()
	keyPEM := generateTestKey(t)

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// 1. Build the Go binary in a container.
	binPath := buildTestBinary(t, engine)

	// 2. Pack: assemble OCI image.
	result, outRoot, _ := packTestImage(t, binPath, keyPEM)
	defer outRoot.Close() //nolint:errcheck // os.Root.Close on temp dir; error is not actionable in test

	t.Logf("image digest: %s", result.Digest)

	// 3. Verify digest format.
	if !strings.HasPrefix(result.Digest, "sha256:") {
		t.Errorf("unexpected digest format: %s", result.Digest)
	}

	// 4. Load into local store.
	regClient := &registry.Client{Engine: engine}
	digest, err := regClient.LoadOCITar(ctx, outRoot, "image.tar")
	if err != nil {
		t.Fatalf("load OCI tar: %v", err)
	}
	t.Logf("loaded as: %s", digest)

	// 5. Inspect the loaded image via its local tag.
	localTag := "localhost/strike:" + strings.TrimPrefix(digest, "sha256:")[:12]
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
	outDir2 := t.TempDir()
	outRoot2, openErr := os.OpenRoot(outDir2)
	if openErr != nil {
		t.Fatalf("open root 2: %v", openErr)
	}
	defer outRoot2.Close() //nolint:errcheck // os.Root.Close on temp dir; error is not actionable in test

	result2, err := executor.Pack(context.Background(), executor.PackOpts{
		Spec: &lane.PackSpec{
			Base: lane.ImageRef(staticBase),
			Files: []lane.PackFile{
				{From: "build.app", Dest: "/app", Mode: 0o755},
			},
			Config: &lane.ImageConfig{
				Entrypoint: []string{"/app"},
				User:       "65534:65534",
			},
		},
		InputPaths:  map[string]string{"build.app": binPath},
		OutputRoot:  outRoot2,
		OutputName:  "image.tar",
		SigningKey:  keyPEM,
		KeyPassword: nil,
	})
	if err != nil {
		t.Fatalf("pack (second run): %v", err)
	}
	if result.Digest != result2.Digest {
		t.Errorf("non-deterministic pack:\n  run 1: %s\n  run 2: %s",
			result.Digest, result2.Digest)
	}
}
