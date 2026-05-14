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
	defer warnClose(rc, "save image")
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("save image %s: read: %w", tag, err)
	}
	return data, nil
}

// ExtractSingleLayer extracts the content of a single-layer OCI image tar
// into destDir. The image must contain exactly one layer. Non-regular,
// non-directory entries (symlinks, devices, etc.) are rejected. Path
// traversal attempts are rejected via os.Root (kernel-enforced) and
// filepath.IsLocal (defensive pre-check).
func ExtractSingleLayer(tarBytes []byte, destDir string) error {
	// Extract OCI layout tar to temp dir; must stay alive until layer read.
	tmpDir, err := os.MkdirTemp(filepath.Dir(destDir), "strike-extract-")
	if err != nil {
		return fmt.Errorf("extract: create temp dir: %w", err)
	}
	defer warnRemoveAll(tmpDir, "extract layout")

	if extractErr := extractTar(bytes.NewReader(tarBytes), tmpDir); extractErr != nil {
		return fmt.Errorf("extract: unpack layout: %w", extractErr)
	}

	layer, layerErr := openSingleLayer(tmpDir)
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

// openSingleLayer reads an OCI layout directory and returns the single layer.
func openSingleLayer(layoutDir string) (v1.Layer, error) {
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

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("extract: read layers: %w", err)
	}
	if len(layers) != 1 {
		return nil, fmt.Errorf("expected single-layer image, found %d layers", len(layers))
	}
	return layers[0], nil
}

// extractLayer extracts an uncompressed OCI layer tar into root.
func extractLayer(layer v1.Layer, root *os.Root) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("uncompress layer: %w", err)
	}
	defer warnClose(rc, "extract layer")

	tr := tar.NewReader(rc)
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return fmt.Errorf("extract: read header: %w", nextErr)
		}

		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("layer entry %q is not a local path", hdr.Name)
		}

		if entryErr := extractEntry(root, hdr, tr); entryErr != nil {
			return entryErr
		}
	}
}

// extractEntry writes a single tar entry into root.
func extractEntry(root *os.Root, hdr *tar.Header, tr io.Reader) error {
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
	default:
		return fmt.Errorf("layer entry %q has unsupported type %d", hdr.Name, hdr.Typeflag)
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
