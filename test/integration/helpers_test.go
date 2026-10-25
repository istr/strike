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

	"github.com/istr/strike/internal/clock"
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
	goImage    = "cgr.dev/chainguard/go@sha256:0a0ba6cee2d535a4e9dcc63d4230be546d3c4c6631b23bc9989992711317649f"
	staticBase = "cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b"
)

// ensureImage materializes an image through the production path if the
// engine store does not resolve it yet.
func ensureImage(t *testing.T, engine container.Engine, ref string) {
	t.Helper()
	c := &registry.Client{Engine: engine}
	if err := c.EnsureImage(context.Background(), primitive.NewImageRef(ref)); err != nil {
		t.Fatalf("EnsureImage %s: %v", ref, err)
	}
}

// buildTestBinary compiles the test Go program in a container and returns
// the binary. The source is seeded into an engine volume and the binary is
// read back from the stopped container's archive, so no host path is bound
// into the container (ADR-035).
func buildTestBinary(t *testing.T, engine container.Engine) []byte {
	t.Helper()
	ctx := context.Background()

	srcRoot, rootErr := os.OpenRoot(filepath.Join("testdata", "src"))
	if rootErr != nil {
		t.Fatalf("open source root: %v", rootErr)
	}
	defer closer.Warn(srcRoot, "buildTestBinary source root")
	var src bytes.Buffer
	tw := tar.NewWriter(&src)
	if addErr := tw.AddFS(srcRoot.FS()); addErr != nil {
		t.Fatalf("tar source: %v", addErr)
	}
	if cErr := tw.Close(); cErr != nil {
		t.Fatalf("close source tar: %v", cErr)
	}

	vol := fmt.Sprintf("strike-itest-build-%d", clock.Wall().UnixNano())
	if volErr := engine.VolumeCreate(ctx, vol); volErr != nil {
		t.Fatalf("volume create: %v", volErr)
	}
	t.Cleanup(func() {
		if rmErr := engine.VolumeRemove(ctx, vol); rmErr != nil {
			t.Logf("WARN volume remove: %v", rmErr)
		}
	})

	var stdout, stderr bytes.Buffer
	id, exitCode, err := engine.ContainerRunHeld(ctx, container.RunOpts{
		Image: goImage,
		Cmd: []string{
			"build", "-C", "/work", "-trimpath",
			"-buildvcs=false", "-ldflags=-s -w",
			"-o", "/work/app", ".",
		},
		Env:      map[string]string{"CGO_ENABLED": "0", "GOCACHE": "/tmp/gocache", "GOPATH": "/tmp/gopath"},
		Stdout:   &stdout,
		Stderr:   &stderr,
		Volume:   &container.VolumeMount{Name: vol, Dest: "/work"},
		CapDrop:  []string{"ALL"},
		ReadOnly: true,
		Tmpfs:    map[string]string{"/tmp": "rw,noexec,nosuid,size=512m"},
	}, []container.Seed{{Path: "/work", Tar: bytes.NewReader(src.Bytes())}})
	if id != "" {
		defer func() {
			if rmErr := engine.ContainerRemove(ctx, id); rmErr != nil {
				t.Logf("WARN container remove: %v", rmErr)
			}
		}()
	}
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("build: exit code %d\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}

	rc, archErr := engine.ContainerArchive(ctx, id, "/work/app")
	if archErr != nil {
		t.Fatalf("archive binary: %v", archErr)
	}
	defer closer.Warn(rc, "buildTestBinary archive")
	tr := tar.NewReader(rc)
	if _, nextErr := tr.Next(); nextErr != nil {
		t.Fatalf("binary not in archive: %v", nextErr)
	}
	bin, readErr := io.ReadAll(tr)
	if readErr != nil {
		t.Fatalf("read binary: %v", readErr)
	}
	t.Logf("binary: %d bytes", len(bin))
	return bin
}

// packInputTars returns the canonical content tar map the test pack spec
// expects: the binary landing at /app with mode 0o755, the shape
// registry.PackTarFromImage emits for a single-file selection.
func packInputTars(t *testing.T, content []byte) map[string][]byte {
	t.Helper()

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
func packTestImage(t *testing.T, bin []byte) *executor.PackResult {
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
		InputTars: packInputTars(t, bin),
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
