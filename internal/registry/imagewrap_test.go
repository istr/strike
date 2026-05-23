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
	"github.com/istr/strike/internal/registry"
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
	return &container.ImageInfo{Digest: digest}, nil
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

	if extractErr := registry.ExtractTarForTest(data, root); extractErr != nil {
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

func TestWrapFileAsImage_LoadsAndTags(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello")
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	tag := "localhost/strike/test-lane/test-step:abc123"

	digest, size, err := client.WrapFileAsImage(context.Background(), root, "test.txt", tag)
	if err != nil {
		t.Fatalf("WrapFileAsImage: %v", err)
	}
	if digest.IsZero() {
		t.Fatal("expected non-zero digest")
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
	if len(eng.loadBodies) != 1 {
		t.Fatalf("expected 1 load call, got %d", len(eng.loadBodies))
	}
	if len(eng.loadBodies[0]) == 0 {
		t.Fatal("load body is empty")
	}
	if len(eng.tags) != 1 || eng.tags[0] != tag {
		t.Fatalf("expected tag %q, got %v", tag, eng.tags)
	}
}

func TestWrapDirectoryAsImage_LoadsAndTags(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "mydir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "a.txt"), []byte("aaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "b.txt"), []byte("bbb"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	tag := "localhost/strike/test-lane/test-step:def456"

	digest, size, err := client.WrapDirectoryAsImage(context.Background(), root, "mydir", tag)
	if err != nil {
		t.Fatalf("WrapDirectoryAsImage: %v", err)
	}
	if digest.IsZero() {
		t.Fatal("expected non-zero digest")
	}
	if size != 6 { // 3 ("aaa") + 3 ("bbb")
		t.Errorf("size = %d, want 6", size)
	}
	if len(eng.loadBodies) != 1 {
		t.Fatalf("expected 1 load call, got %d", len(eng.loadBodies))
	}
	if len(eng.tags) != 1 || eng.tags[0] != tag {
		t.Fatalf("expected tag %q, got %v", tag, eng.tags)
	}
}

func TestWrapFileAsImage_Deterministic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "det.txt"), []byte("deterministic content"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng1 := &wrapEngine{}
	client1 := &registry.Client{Engine: eng1}
	if _, _, err := client1.WrapFileAsImage(context.Background(), root, "det.txt", "localhost/strike/l/s:h1"); err != nil {
		t.Fatal(err)
	}

	eng2 := &wrapEngine{}
	client2 := &registry.Client{Engine: eng2}
	if _, _, err := client2.WrapFileAsImage(context.Background(), root, "det.txt", "localhost/strike/l/s:h2"); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(eng1.loadBodies[0], eng2.loadBodies[0]) {
		t.Error("image tar is not deterministic across calls")
	}
}

func TestWrapDirectoryAsImage_Deterministic(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "detdir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "x.txt"), []byte("xxx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "y.txt"), []byte("yyy"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng1 := &wrapEngine{}
	client1 := &registry.Client{Engine: eng1}
	if _, _, err := client1.WrapDirectoryAsImage(context.Background(), root, "detdir", "localhost/strike/l/s:h1"); err != nil {
		t.Fatal(err)
	}

	eng2 := &wrapEngine{}
	client2 := &registry.Client{Engine: eng2}
	if _, _, err := client2.WrapDirectoryAsImage(context.Background(), root, "detdir", "localhost/strike/l/s:h2"); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(eng1.loadBodies[0], eng2.loadBodies[0]) {
		t.Error("directory image tar is not deterministic across calls")
	}
}

func TestWrapFileAsImage_ContentSizeAnnotation(t *testing.T) {
	dir := t.TempDir()
	content := []byte("annotation-check")
	if err := os.WriteFile(filepath.Join(dir, "ann.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}

	_, _, err := client.WrapFileAsImage(context.Background(), root, "ann.txt", "localhost/strike/l/s:h")
	if err != nil {
		t.Fatal(err)
	}

	ann := extractAnnotations(t, eng.loadBodies[0])
	sizeStr, ok := ann[registry.ContentSizeAnnotation]
	if !ok {
		t.Fatal("missing content-size annotation")
	}
	if sizeStr != "16" { // len("annotation-check")
		t.Errorf("content-size = %q, want %q", sizeStr, "16")
	}
}

// extractAnnotations extracts manifest annotations from an OCI layout tar.
func extractAnnotations(t *testing.T, data []byte) map[string]string {
	t.Helper()
	dir := t.TempDir()
	root := mustOpenRoot(t, dir)
	if err := registry.ExtractTarForTest(data, root); err != nil {
		t.Fatal(err)
	}
	lp, err := layout.FromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Manifests) == 0 {
		t.Fatal("empty index")
	}
	img, err := idx.Image(manifest.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	return m.Annotations
}

func TestWrapFileAsImage_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	_, _, err := client.WrapFileAsImage(context.Background(), root, "link.txt", "localhost/strike/l/s:h")
	if err == nil {
		t.Fatal("expected error for symlink")
	}
}

func TestWrapDirectoryAsImage_AcceptsContainedSymlink(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "mydir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "real.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Relative target within the wrapped tree -> contained.
	if err := os.Symlink("real.txt", filepath.Join(subDir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	if _, _, err := client.WrapDirectoryAsImage(context.Background(), root, "mydir", "localhost/strike/l/s:h"); err != nil {
		t.Fatalf("contained symlink should wrap: %v", err)
	}
}

func TestWrapDirectoryAsImage_RejectsEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "mydir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Relative target that climbs out of the wrapped tree.
	if err := os.Symlink("../escape.txt", filepath.Join(subDir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	if _, _, err := client.WrapDirectoryAsImage(context.Background(), root, "mydir", "localhost/strike/l/s:h"); err == nil {
		t.Fatal("expected error for escaping symlink")
	}
}

func TestWrapDirectoryAsImage_RejectsAbsoluteSymlink(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "mydir")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(subDir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)
	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	if _, _, err := client.WrapDirectoryAsImage(context.Background(), root, "mydir", "localhost/strike/l/s:h"); err == nil {
		t.Fatal("expected error for absolute symlink")
	}
}

func TestWrapDirectoryAsImage_SymlinkDeterministic(t *testing.T) {
	build := func() []byte {
		dir := t.TempDir()
		subDir := filepath.Join(dir, "mydir")
		if err := os.MkdirAll(subDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(subDir, "real.txt"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real.txt", filepath.Join(subDir, "link.txt")); err != nil {
			t.Fatal(err)
		}
		root := mustOpenRoot(t, dir)
		eng := &wrapEngine{}
		client := &registry.Client{Engine: eng}
		if _, _, err := client.WrapDirectoryAsImage(context.Background(), root, "mydir", "localhost/strike/l/s:h"); err != nil {
			t.Fatal(err)
		}
		return eng.loadBodies[0]
	}
	if !bytes.Equal(build(), build()) {
		t.Error("symlink-bearing directory image tar is not deterministic")
	}
}

func TestWrapImageOutputAsImage_LoadsExistingTar(t *testing.T) {
	// Build a minimal valid OCI image tar by wrapping a file first,
	// capturing the tar, then using it as input to WrapImageOutputAsImage.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "src.txt"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := mustOpenRoot(t, dir)

	// First, capture the tar bytes from a file wrap.
	eng1 := &wrapEngine{}
	client1 := &registry.Client{Engine: eng1}
	if _, _, err := client1.WrapFileAsImage(context.Background(), root, "src.txt", "localhost/strike/l/s:capture"); err != nil {
		t.Fatal(err)
	}

	// Write the captured tar to a file.
	if err := os.WriteFile(filepath.Join(dir, "image.tar"), eng1.loadBodies[0], 0o600); err != nil {
		t.Fatal(err)
	}

	// Now load it via WrapImageOutputAsImage.
	eng2 := &wrapEngine{}
	client2 := &registry.Client{Engine: eng2}
	tag := "localhost/strike/test-lane/img-step:hash"
	digest, size, err := client2.WrapImageOutputAsImage(context.Background(), root, "image.tar", tag)
	if err != nil {
		t.Fatalf("WrapImageOutputAsImage: %v", err)
	}
	if digest.IsZero() {
		t.Fatal("expected non-zero digest")
	}
	if size <= 0 {
		t.Errorf("size should be positive, got %d", size)
	}
	if len(eng2.loadBodies) != 1 {
		t.Fatalf("expected 1 load call, got %d", len(eng2.loadBodies))
	}
	if len(eng2.tags) != 1 || eng2.tags[0] != tag {
		t.Fatalf("expected tag %q, got %v", tag, eng2.tags)
	}
}
