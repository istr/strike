package integration_test

import (
	"archive/tar"
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
	goImage    = "cgr.dev/chainguard/go@sha256:694c79dc301a249df5f2541aff2d82718d4ef3ff36bfa8a9eaee55ecadd40d16"
	staticBase = "cgr.dev/chainguard/static@sha256:f51c2493951313c3ad4069080b2814ffb6ed6fe3909dabeb84a9482f42d5600b"
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

// packInputTars reads the built binary and returns the canonical content
// tar map the test pack spec expects: the binary landing at /app with mode
// 0o755, the shape registry.PackTarFromImage emits for a single-file
// selection. The binary is read through os.Root, scoped to its directory.
func packInputTars(t *testing.T, binPath string) map[string][]byte {
	t.Helper()
	root, rootErr := os.OpenRoot(filepath.Dir(binPath))
	if rootErr != nil {
		t.Fatalf("open binary root: %v", rootErr)
	}
	defer closer.Warn(root, "packInputTars root")
	f, openErr := root.Open(filepath.Base(binPath))
	if openErr != nil {
		t.Fatalf("open binary: %v", openErr)
	}
	content, readErr := io.ReadAll(f)
	closer.Warn(f, "packInputTars binary")
	if readErr != nil {
		t.Fatalf("read binary: %v", readErr)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// Uid, Gid, ModTime intentionally zero for determinism.
	hdr := &tar.Header{Name: "app", Mode: 0o755, Typeflag: tar.TypeReg, Size: int64(len(content))}
	if hdrErr := tw.WriteHeader(hdr); hdrErr != nil {
		t.Fatalf("write tar header: %v", hdrErr)
	}
	if _, wErr := tw.Write(content); wErr != nil {
		t.Fatalf("write tar content: %v", wErr)
	}
	if cErr := tw.Close(); cErr != nil {
		t.Fatalf("close tar: %v", cErr)
	}
	return map[string][]byte{"/app": buf.Bytes()}
}

// packTestImage assembles an OCI image from a binary and returns
// the pack result.
func packTestImage(t *testing.T, binPath string) *executor.PackResult {
	t.Helper()

	result, packErr := executor.Pack(executor.PackOpts{
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
		InputTars: packInputTars(t, binPath),
	})
	if packErr != nil {
		t.Fatalf("pack: %v", packErr)
	}
	return result
}

// loadOCITar loads the main image from an OCI tar archive into the local
// container store and returns the manifest digest. Reimplemented here
// using only exported registry functions so that production code does not
// carry test-only helpers.
func loadOCITar(ctx context.Context, c *registry.Client, data []byte) (primitive.Digest, error) {
	tmpDir, err := os.MkdirTemp("", "strike-load-")
	if err != nil {
		return "", err
	}
	defer closer.Remove(tmpDir, "loadOCITar")

	tmpRoot, err := os.OpenRoot(tmpDir)
	if err != nil {
		return "", err
	}
	defer closer.Warn(tmpRoot, "loadOCITar root")

	if extractErr := regtest.ExtractTar(data, tmpRoot); extractErr != nil {
		return "", fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		return "", fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		return "", fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("read index manifest: %w", err)
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
		return "", err
	}
	if img == nil {
		return "", fmt.Errorf("no annotated main image in %d-manifest archive", len(manifest.Manifests))
	}

	tarData, err := regtest.LayoutTar(img, descAnn)
	if err != nil {
		return "", err
	}

	id, err := c.Engine.ImageLoad(ctx, bytes.NewReader(tarData))
	if err != nil {
		return "", err
	}

	d, err := c.InspectDigest(ctx, id)
	if err != nil {
		return "", err
	}

	localTag := "localhost/strike:" + string(d.Hex()[:12])
	if tagErr := c.Engine.ImageTag(ctx, id, localTag); tagErr != nil {
		return "", fmt.Errorf("image tag: %w", tagErr)
	}

	return d, nil
}
