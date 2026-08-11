package integration_test

import (
	"io"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

// TestPackLayoutPayloadOnly proves a pack output is an unsigned intermediate:
// its OCI layout carries only the payload image and no SBOM referrers. SBOM
// generation and publication happen once, at deploy (ADR-051 D1/D3).
func TestPackLayoutPayloadOnly(t *testing.T) {
	engine := testutil.RequireEngine(t)

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	binPath := buildTestBinary(t, engine)

	outDir := t.TempDir()
	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.CloseLog(t, outRoot, "pack layout test outRoot")

	result, err := executor.Pack(executor.PackOpts{
		Spec: &lane.PackSpec{
			Base: primitive.ImageRef(staticBase),
			Files: []lane.PackFile{
				{From: lane.OutputRef{Step: "build", Output: "app"}, Dest: "/app", Mode: 0o755},
			},
			Config: &lane.ImageConfig{
				Entrypoint: []string{"/app"},
				User:       primitive.UserSpecPtr("65534:65534"),
			},
		},
		InputPaths: map[string]string{"/app": binPath},
		OutputRoot: outRoot,
		OutputName: "image.tar",
	})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	imgDigest := result.Digest.String()
	t.Logf("image digest: %s", imgDigest)

	// Extract the OCI layout tar and inspect its contents.
	tarFile, err := outRoot.Open("image.tar")
	if err != nil {
		t.Fatalf("open image.tar: %v", err)
	}
	tarData, err := io.ReadAll(tarFile)
	closer.Warn(tarFile, "pack layout test tar")
	if err != nil {
		t.Fatalf("read image.tar: %v", err)
	}

	layoutDir := t.TempDir()
	layoutRoot, err := os.OpenRoot(layoutDir)
	if err != nil {
		t.Fatalf("open layout root: %v", err)
	}
	defer testutil.CloseLog(t, layoutRoot, "pack layout test layoutRoot")

	if extractErr := regtest.ExtractTar(tarData, layoutRoot); extractErr != nil {
		t.Fatalf("extract layout: %v", extractErr)
	}

	lp, err := layout.FromPath(layoutDir)
	if err != nil {
		t.Fatalf("open layout: %v", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("read index manifest: %v", err)
	}

	if len(manifest.Manifests) != 1 {
		t.Fatalf("layout manifests = %d, want 1 (payload only)", len(manifest.Manifests))
	}
	refName, ok := manifest.Manifests[0].Annotations["org.opencontainers.image.ref.name"]
	if !ok {
		t.Fatal("payload manifest missing org.opencontainers.image.ref.name annotation")
	}
	if refName != imgDigest {
		t.Errorf("ref.name = %q, want %q", refName, imgDigest)
	}
}
