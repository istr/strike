package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

// Digest-pinned image references matching lane.yaml.
const (
	goImage    = "cgr.dev/chainguard/go@sha256:7596cc2ec314f54001ca15753e5ac11e9e10106fde96cd24f6a886a2eb770dd8"
	staticBase = "cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b"
)

// ensureImage pulls an image if it is not already in the local store.
func ensureImage(t *testing.T, engine container.Engine, ref string) {
	t.Helper()
	ctx := context.Background()
	exists, err := engine.ImageExists(ctx, ref)
	if err != nil {
		t.Fatalf("image exists check: %v", err)
	}
	if exists {
		return
	}
	t.Logf("pulling %s ...", ref)
	if pullErr := engine.ImagePull(ctx, ref); pullErr != nil {
		t.Fatalf("image pull %s: %v", ref, pullErr)
	}
}

// buildTestBinary compiles the test Go program in a container and returns
// the path to the resulting binary.
func buildTestBinary(t *testing.T, engine container.Engine) string {
	t.Helper()
	srcDir, absErr := filepath.Abs(filepath.Join("testdata", "src"))
	if absErr != nil {
		t.Fatalf("abs path: %v", absErr)
	}
	outDir := t.TempDir()
	ctx := context.Background()

	var stdout, stderr bytes.Buffer
	exitCode, err := engine.ContainerRun(ctx, container.RunOpts{
		Image: goImage,
		Cmd: []string{
			"build", "-C", "/src", "-trimpath",
			"-buildvcs=false", "-ldflags=-s -w",
			"-o", "/out/app", ".",
		},
		Env:    map[string]string{"CGO_ENABLED": "0", "GOCACHE": "/tmp/gocache", "GOPATH": "/tmp/gopath"},
		Stdout: &stdout,
		Stderr: &stderr,
		Mounts: []container.Mount{
			{Source: srcDir, Target: "/src", ReadOnly: true},
			{Source: outDir, Target: "/out"},
		},
		CapDrop:  []string{"ALL"},
		ReadOnly: true,
		Tmpfs:    map[string]string{"/tmp": "rw,noexec,nosuid,size=512m"},
		Remove:   true,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("build: exit code %d\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}

	binPath := filepath.Join(outDir, "app")
	info, statErr := os.Stat(binPath)
	if statErr != nil {
		t.Fatalf("binary not found: %v", statErr)
	}
	t.Logf("binary: %s (%d bytes)", binPath, info.Size())
	return binPath
}

// packTestImage assembles an OCI image from a binary and returns
// the pack result and the root-scoped output directory.
func packTestImage(t *testing.T, binPath string) (*executor.PackResult, *os.Root, string) {
	t.Helper()
	outDir := t.TempDir()
	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		t.Fatal(err)
	}

	result, packErr := executor.Pack(executor.PackOpts{
		Spec: &lane.PackSpec{
			Base: primitive.ImageRef(staticBase),
			Files: []lane.PackFile{
				{From: lane.OutputRef{Step: "build", Output: "app"}, Dest: "/app", Mode: 0o755},
			},
			Config: &lane.ImageConfig{
				Entrypoint: []string{"/app"},
				User:       lane.Ptr("65534:65534"),
			},
		},
		InputPaths: map[string]string{"/app": binPath},
		OutputRoot: outRoot,
		OutputName: "image.tar",
	})
	if packErr != nil {
		closer.Warn(outRoot, "packTestImage error cleanup")
		t.Fatalf("pack: %v", packErr)
	}
	return result, outRoot, outDir
}

// loadOCITar loads the main image from an OCI tar archive into the local
// container store and returns the manifest digest. Reimplemented here
// using only exported registry functions so that production code does not
// carry test-only helpers.
func loadOCITar(ctx context.Context, c *registry.Client, root *os.Root, relPath string) (lane.DigestRef, error) {
	f, err := root.Open(relPath)
	if err != nil {
		return lane.DigestRef{}, err
	}
	data, err := io.ReadAll(f)
	closer.Warn(f, "loadOCITar")
	if err != nil {
		return lane.DigestRef{}, err
	}

	tmpDir, err := os.MkdirTemp("", "strike-load-")
	if err != nil {
		return lane.DigestRef{}, err
	}
	defer closer.Remove(tmpDir, "loadOCITar")

	tmpRoot, err := os.OpenRoot(tmpDir)
	if err != nil {
		return lane.DigestRef{}, err
	}
	defer closer.Warn(tmpRoot, "loadOCITar root")

	if extractErr := regtest.ExtractTar(data, tmpRoot); extractErr != nil {
		return lane.DigestRef{}, fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("read index manifest: %w", err)
	}

	var img v1.Image
	var descAnn map[string]string
	switch {
	case len(manifest.Manifests) == 1:
		img, err = idx.Image(manifest.Manifests[0].Digest)
		descAnn = manifest.Manifests[0].Annotations
	default:
		for _, desc := range manifest.Manifests {
			if _, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
				img, err = idx.Image(desc.Digest)
				descAnn = desc.Annotations
				break
			}
		}
	}
	if err != nil {
		return lane.DigestRef{}, err
	}
	if img == nil {
		return lane.DigestRef{}, fmt.Errorf("no annotated main image in %d-manifest archive", len(manifest.Manifests))
	}

	tarData, err := regtest.LayoutTar(img, descAnn)
	if err != nil {
		return lane.DigestRef{}, err
	}

	id, err := c.Engine.ImageLoad(ctx, bytes.NewReader(tarData))
	if err != nil {
		return lane.DigestRef{}, err
	}

	d, err := c.InspectDigest(ctx, id)
	if err != nil {
		return lane.DigestRef{}, err
	}

	localTag := "localhost/strike:" + string(d.Hex[:12])
	if tagErr := c.Engine.ImageTag(ctx, id, localTag); tagErr != nil {
		return lane.DigestRef{}, fmt.Errorf("image tag: %w", tagErr)
	}

	return d, nil
}
