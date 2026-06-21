package registry

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/closer"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/istr/strike/internal/container"
)

// SaveImage exports an image from the engine as an OCI archive tar.
func SaveImage(ctx context.Context, engine container.Engine, tag string) ([]byte, error) {
	rc, err := engine.ImageSave(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("save image %s: %w", tag, err)
	}
	defer closer.Warn(rc, "save image")
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("save image %s: read: %w", tag, err)
	}
	return data, nil
}

// LayerDiffIDs returns the image's layer uncompressed-content digests (the
// config rootfs.diff_ids) in canonical layer order. tarBytes is an OCI-layout
// archive from SaveImage. The diff_id is the per-layer key stable across an
// engine load/save round-trip (ADR-046); a cache hit recovers each output's
// LayerDiffID from this ordered list, bound to step.Outputs by the canonical
// layer ordering the producer assembles.
func LayerDiffIDs(tarBytes []byte) ([]string, error) {
	dir, err := os.MkdirTemp("", "strike-diffids-")
	if err != nil {
		return nil, fmt.Errorf("diff ids: create temp dir: %w", err)
	}
	defer closer.Remove(dir, "diff ids layout")

	root, rootErr := os.OpenRoot(dir)
	if rootErr != nil {
		return nil, fmt.Errorf("diff ids: open temp root: %w", rootErr)
	}
	defer closer.Warn(root, "diff ids layout root")

	if exErr := extractTar(bytes.NewReader(tarBytes), root); exErr != nil {
		return nil, fmt.Errorf("diff ids: unpack layout: %w", exErr)
	}

	lp, err := layout.FromPath(dir)
	if err != nil {
		return nil, fmt.Errorf("diff ids: open layout: %w", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("diff ids: read index: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("diff ids: read manifest: %w", err)
	}
	if len(im.Manifests) != 1 {
		return nil, fmt.Errorf("diff ids: expected single image in layout, found %d", len(im.Manifests))
	}
	img, err := idx.Image(im.Manifests[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("diff ids: open image: %w", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("diff ids: read config: %w", err)
	}
	ids := make([]string, len(cfg.RootFS.DiffIDs))
	for i, h := range cfg.RootFS.DiffIDs {
		ids[i] = h.String()
	}
	return ids, nil
}

// ExtractLayer extracts the content of the identified layer from an OCI image
// tar into destDir. layerDiffID is matched against the image config's
// rootfs.diff_ids -- the uncompressed-content digest is the only per-layer key
// stable across an engine load/save round-trip. Non-regular, non-directory
// entries (symlinks, devices, etc.) are rejected. Path traversal attempts are
// rejected via os.Root (kernel-enforced) and filepath.IsLocal (defensive
// pre-check).
func ExtractLayer(tarBytes []byte, layerDiffID, destDir string) error {
	// Extract OCI layout tar to temp dir; must stay alive until layer read.
	tmpDir, err := os.MkdirTemp(filepath.Dir(destDir), "strike-extract-")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}
	defer closer.Remove(tmpDir, "extract layout")

	tmpRoot, rootErr := os.OpenRoot(tmpDir)
	if rootErr != nil {
		return fmt.Errorf("extract: open temp root: %w", rootErr)
	}
	defer closer.Warn(tmpRoot, "extract layout root")

	if extractErr := extractTar(bytes.NewReader(tarBytes), tmpRoot); extractErr != nil {
		return fmt.Errorf("extract: unpack layout: %w", extractErr)
	}

	layer, layerErr := openLayer(tmpDir, layerDiffID)
	if layerErr != nil {
		return layerErr
	}

	root, err := os.OpenRoot(destDir)
	if err != nil {
		return fmt.Errorf("open extraction root: %w", err)
	}
	defer func() {
		if cerr := root.Close(); cerr != nil {
			log.Printf("WARN close extraction root: %v", cerr)
		}
	}()

	return extractLayer(layer, root)
}

// openLayer reads an OCI layout directory and returns the layer whose
// uncompressed-content digest (diff_id) equals layerDiffID. The diff_id is the
// only per-layer key stable across an engine load/save round-trip, which
// strips descriptor annotations and re-compresses blobs (ADR-046).
func openLayer(layoutDir, layerDiffID string) (v1.Layer, error) {
	lp, err := layout.FromPath(layoutDir)
	if err != nil {
		return nil, fmt.Errorf("extract: open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("extract: read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("extract: read manifest: %w", err)
	}
	if len(manifest.Manifests) != 1 {
		return nil, fmt.Errorf("expected single image in layout, found %d", len(manifest.Manifests))
	}

	img, err := idx.Image(manifest.Manifests[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("extract: open image: %w", err)
	}

	diffID, err := v1.NewHash(layerDiffID)
	if err != nil {
		return nil, fmt.Errorf("extract: parse layer diff id %q: %w", layerDiffID, err)
	}
	layer, err := img.LayerByDiffID(diffID)
	if err != nil {
		return nil, fmt.Errorf("extract: output layer %q not found in step image: %w", layerDiffID, err)
	}
	return layer, nil
}

// extractLayer extracts an uncompressed OCI layer tar into root. Layer tars
// are user content and may carry contained symlinks.
func extractLayer(layer v1.Layer, root *os.Root) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("uncompress layer: %w", err)
	}
	defer closer.Warn(rc, "extract layer")
	return extractTarStream(rc, root, true)
}

// extractTarStream extracts a tar stream into root. Every entry path must be
// local (filepath.IsLocal). Directories and regular files preserve their tar
// mode. Symlinks are created verbatim when allowSymlinks is true and rejected
// otherwise; os.Root never follows them. Any other entry type is rejected.
func extractTarStream(r io.Reader, root *os.Root, allowSymlinks bool) error {
	tr := tar.NewReader(r)
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return fmt.Errorf("extract: read header: %w", nextErr)
		}

		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("tar entry %q is not a local path", hdr.Name)
		}

		if entryErr := extractEntry(root, hdr, tr, allowSymlinks); entryErr != nil {
			return entryErr
		}
	}
}

// extractEntry writes a single tar entry into root. Symlinks are honored only
// when allowSymlinks is true; otherwise a symlink entry is rejected.
func extractEntry(root *os.Root, hdr *tar.Header, tr io.Reader, allowSymlinks bool) error {
	mode := hdr.FileInfo().Mode().Perm()

	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := root.MkdirAll(hdr.Name, mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", hdr.Name, err)
		}
	case tar.TypeReg:
		if err := extractRegularFile(root, hdr.Name, tr, hdr.Size, mode); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if !allowSymlinks {
			return fmt.Errorf("tar entry %q is a symlink, which is not allowed here", hdr.Name)
		}
		if err := extractSymlink(root, hdr.Name, hdr.Linkname); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tar entry %q has unsupported type %d", hdr.Name, hdr.Typeflag)
	}
	return nil
}

// extractSymlink creates a symlink entry within root. The link is created,
// never followed: os.Root.Symlink confines the link's location to root and
// refuses to traverse it for later writes, and the target is stored verbatim
// without inspection. Containment of the target is not decided here -- a link
// valid in the full artifact must survive extraction so a whole-artifact
// mount works. Whether the target stays inside a given consuming mount is
// decided per mountpoint at mount construction (validateMountSymlinks).
func extractSymlink(root *os.Root, name, target string) error {
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return fmt.Errorf("mkdir parent %s: %w", name, err)
	}
	if err := root.Symlink(target, name); err != nil {
		return fmt.Errorf("symlink %s: %w", name, err)
	}
	return nil
}

// extractRegularFile writes a regular file entry into root.
func extractRegularFile(root *os.Root, name string, r io.Reader, size int64, mode os.FileMode) error {
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return fmt.Errorf("mkdir parent %s: %w", name, err)
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if _, cpErr := io.CopyN(f, r, size); cpErr != nil {
		return errors.Join(fmt.Errorf("write %s: %w", name, cpErr), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	return nil
}
