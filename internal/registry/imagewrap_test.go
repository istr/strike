package registry_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/closer"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

// wrapEngine captures ImageLoad request bodies and simulates tag/inspect.
// It extracts the manifest digest from the loaded OCI tar so that digest
// verification in loadTagVerify succeeds.
type wrapEngine struct {
	container.Engine
	lastDigest string
	loadBodies [][]byte
	tags       []string
	inspected  []string
}

func (e *wrapEngine) ImageLoad(_ context.Context, input io.Reader) (string, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return "", err
	}
	e.loadBodies = append(e.loadBodies, data)

	// Extract manifest digest from the OCI layout tar.
	if digest, extractErr := extractDigestFromTar(data); extractErr == nil {
		e.lastDigest = digest
	}
	return "sha256:loadedid", nil
}

func (e *wrapEngine) ImageTag(_ context.Context, _, target string) error {
	e.tags = append(e.tags, target)
	return nil
}

func (e *wrapEngine) ImageInspect(_ context.Context, ref string) (*container.ImageInfo, error) {
	e.inspected = append(e.inspected, ref)
	digest := e.lastDigest
	if digest == "" {
		digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	}
	return &container.ImageInfo{Digest: primitive.Digest(digest)}, nil
}

// extractDigestFromTar extracts the manifest digest from an OCI layout tar.
func extractDigestFromTar(data []byte) (string, error) {
	dir, err := os.MkdirTemp("", "wraptest-")
	if err != nil {
		return "", err
	}
	defer closer.Remove(dir, "wraptest scratch")

	root, rootErr := os.OpenRoot(dir)
	if rootErr != nil {
		return "", rootErr
	}
	defer closer.Warn(root, "wraptest extract root")

	if extractErr := regtest.ExtractTar(data, root); extractErr != nil {
		return "", extractErr
	}
	lp, err := layout.FromPath(dir)
	if err != nil {
		return "", err
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		return "", err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", err
	}
	if len(manifest.Manifests) == 0 {
		return "", err
	}
	d := manifest.Manifests[0].Digest
	return d.Algorithm + ":" + d.Hex, nil
}

func (e *wrapEngine) ImageExists(_ context.Context, _ string) (bool, error) { return false, nil }
func (e *wrapEngine) ImagePull(_ context.Context, _ string) error           { return nil }
func (e *wrapEngine) ImagePush(_ context.Context, _ string) error           { return nil }

func (e *wrapEngine) ImageSave(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (e *wrapEngine) Ping(_ context.Context) error        { return nil }
func (e *wrapEngine) TLSIdentity() *container.TLSIdentity { return nil }
func (e *wrapEngine) Identity() *container.EngineIdentity { return nil }
func (e *wrapEngine) Info(_ context.Context) error        { return nil }

func (e *wrapEngine) ContainerRun(_ context.Context, _ container.RunOpts) (int, error) {
	return 0, nil
}

func (e *wrapEngine) ContainerRunHeld(_ context.Context, _ container.RunOpts, _ []container.Seed) (string, int, error) {
	return "", 0, nil
}

func (e *wrapEngine) ContainerArchive(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (e *wrapEngine) ContainerRemove(_ context.Context, _ string) error             { return nil }
func (e *wrapEngine) VolumeCreate(_ context.Context, _ string) error                { return nil }
func (e *wrapEngine) SeedVolumes(_ context.Context, _ []container.VolumeSeed) error { return nil }
func (e *wrapEngine) VolumeRemove(_ context.Context, _ string) error                { return nil }

func TestWrapImageOutputAsImage_LoadsExistingTar(t *testing.T) {
	// Build a minimal valid OCI image tar via regtest, then use it as input
	// to WrapImageOutputAsImage.
	tarBytes, _, err := regtest.BuildImageTar("src.txt", []byte("source"))
	if err != nil {
		t.Fatalf("BuildImageTar: %v", err)
	}

	dir := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(dir, "image.tar"), tarBytes, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	tag := "localhost/strike/test-lane/img-step:hash"
	digest, size, err := client.WrapImageOutputAsImage(context.Background(), root, "image.tar", tag)
	if err != nil {
		t.Fatalf("WrapImageOutputAsImage: %v", err)
	}
	if digest.IsZero() {
		t.Fatal("expected non-zero digest")
	}
	if size <= 0 {
		t.Errorf("size should be positive, got %d", size)
	}
	if len(eng.loadBodies) != 1 {
		t.Fatalf("expected 1 load call, got %d", len(eng.loadBodies))
	}
	if len(eng.tags) != 1 || eng.tags[0] != tag {
		t.Fatalf("expected tag %q, got %v", tag, eng.tags)
	}
}
