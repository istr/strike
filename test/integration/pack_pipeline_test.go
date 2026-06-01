package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

func TestPackPipeline(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()
	keyPEM := generateTestKey(t)

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// 1. Build the Go binary in a container.
	binPath := buildTestBinary(t, engine)

	// 2. Pack: assemble OCI image.
	result, outRoot, _ := packTestImage(t, binPath, keyPEM)
	defer testutil.CloseLog(t, outRoot, "pack pipeline outRoot")

	t.Logf("image digest: %s", result.Digest)

	// 3. Verify digest format.
	if result.Digest.Algorithm != "sha256" {
		t.Errorf("unexpected digest algorithm: %s", result.Digest.Algorithm)
	}

	// 4. Load into local store.
	regClient := &registry.Client{Engine: engine}
	digest, err := loadOCITar(ctx, regClient, outRoot, "image.tar")
	if err != nil {
		t.Fatalf("load OCI tar: %v", err)
	}
	t.Logf("loaded as: %s", digest)

	// 5. Inspect the loaded image via its local tag.
	localTag := "localhost/strike:" + digest.Hex[:12]
	imgInfo, err := engine.ImageInspect(ctx, localTag)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if imgInfo.Size == 0 {
		t.Error("loaded image has zero size")
	}
	if imgInfo.Digest != digest.String() {
		t.Errorf("digest mismatch: inspect=%s, load=%s", imgInfo.Digest, digest)
	}

	// 6. Verify determinism: pack again, same digest.
	outDir2 := t.TempDir()
	outRoot2, openErr := os.OpenRoot(outDir2)
	if openErr != nil {
		t.Fatalf("open root 2: %v", openErr)
	}
	defer testutil.CloseLog(t, outRoot2, "pack pipeline outRoot2")

	result2, err := executor.Pack(context.Background(), executor.PackOpts{
		Spec: &lane.PackSpec{
			Base: lane.ImageRef(staticBase),
			Files: []lane.PackFile{
				{From: "build.app", Dest: "/app", Mode: 0o755},
			},
			Config: &lane.ImageConfig{
				Entrypoint: []string{"/app"},
				User:       lane.Ptr("65534:65534"),
			},
		},
		InputPaths:  map[string]string{"/app": binPath},
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
