package registry

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/closer"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"

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

// ImageFromOCITar assembles an OCI image from an OCI-layout tar, such as the
// archive an engine image export returns, holding every blob in memory. No
// payload reaches the controller host filesystem (ADR-035). The layout must
// hold exactly one image (ADR-046).
func ImageFromOCITar(tarBytes []byte) (v1.Image, error) {
	blobs, indexBytes, err := readOCITarBlobs(tarBytes)
	if err != nil {
		return nil, err
	}

	var idx v1.IndexManifest
	if uErr := json.Unmarshal(indexBytes, &idx); uErr != nil {
		return nil, fmt.Errorf("parse index.json: %w", uErr)
	}
	if len(idx.Manifests) != 1 {
		return nil, fmt.Errorf("expected single image in layout, found %d", len(idx.Manifests))
	}

	raw, err := blobFor(blobs, idx.Manifests[0].Digest, "manifest")
	if err != nil {
		return nil, err
	}
	var manifest v1.Manifest
	if uErr := json.Unmarshal(raw, &manifest); uErr != nil {
		return nil, fmt.Errorf("parse manifest: %w", uErr)
	}
	config, err := blobFor(blobs, manifest.Config.Digest, "config")
	if err != nil {
		return nil, err
	}

	return partial.CompressedToImage(&memImage{
		manifest: manifest,
		raw:      raw,
		config:   config,
		blobs:    blobs,
	})
}

// blobFor returns the layout blob a descriptor digest addresses. what names
// the blob's role for the error message.
func blobFor(blobs map[string][]byte, h v1.Hash, what string) ([]byte, error) {
	key := fmt.Sprintf("blobs/%s/%s", h.Algorithm, h.Hex)
	data, ok := blobs[key]
	if !ok {
		return nil, fmt.Errorf("%s blob %q not found", what, key)
	}
	return data, nil
}

// memImage is an OCI image whose blobs are held in memory. It implements
// partial.CompressedImageCore; partial supplies the rest of v1.Image,
// including the diff_id, which it derives by decompressing the layer.
type memImage struct {
	manifest v1.Manifest
	blobs    map[string][]byte
	raw      []byte
	config   []byte
}

func (i *memImage) RawManifest() ([]byte, error) { return i.raw, nil }

func (i *memImage) RawConfigFile() ([]byte, error) { return i.config, nil }

func (i *memImage) MediaType() (types.MediaType, error) { return i.manifest.MediaType, nil }

// LayerByDigest returns the layer blob a manifest descriptor addresses.
func (i *memImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	for _, desc := range i.manifest.Layers {
		if desc.Digest != h {
			continue
		}
		blob, err := blobFor(i.blobs, h, "layer")
		if err != nil {
			return nil, err
		}
		return &memLayer{desc: desc, blob: blob}, nil
	}
	return nil, fmt.Errorf("layer %s not listed in manifest", h)
}

// memLayer is one in-memory layer blob, exposed as a compressed layer. It
// deliberately carries no DiffID method: partial.CompressedToLayer delegates
// to one when the layer provides it, and a DiffID here would report the
// compressed digest where the uncompressed content hash is meant.
type memLayer struct {
	desc v1.Descriptor
	blob []byte
}

func (l *memLayer) Digest() (v1.Hash, error) { return l.desc.Digest, nil }

func (l *memLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.blob)), nil
}

func (l *memLayer) Size() (int64, error) { return int64(len(l.blob)), nil }

func (l *memLayer) MediaType() (types.MediaType, error) { return l.desc.MediaType, nil }

// LayerDiffIDs returns the image's layer uncompressed-content digests (the
// config rootfs.diff_ids) in canonical layer order. tarBytes is an OCI-layout
// archive from SaveImage. The diff_id is the per-layer key stable across an
// engine load/save round-trip (ADR-046); a cache hit recovers each output's
// LayerDiffID from this ordered list, bound to step.Outputs by the canonical
// layer ordering the producer assembles.
func LayerDiffIDs(tarBytes []byte) ([]string, error) {
	img, err := ImageFromOCITar(tarBytes)
	if err != nil {
		return nil, fmt.Errorf("diff ids: %w", err)
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
// tar into destDir. The layer is selected and content-checked by
// layerFromOCITar, so an engine export that does not match what the control
// plane produced fails closed before a byte is written. Layer tars are user
// content and may carry contained symlinks. Path traversal attempts are
// rejected via os.Root (kernel-enforced) and filepath.IsLocal (defensive
// pre-check).
func ExtractLayer(tarBytes []byte, layerDiffID, destDir string) error {
	content, err := layerFromOCITar(tarBytes, layerDiffID)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
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

	return extractTarStream(bytes.NewReader(content), root)
}

// extractTarStream extracts a tar stream into root. Every entry path must be
// local (filepath.IsLocal). Directories and regular files preserve their tar
// mode. Symlinks are created verbatim; os.Root never follows them. Any other
// entry type is rejected.
func extractTarStream(r io.Reader, root *os.Root) error {
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

		if entryErr := extractEntry(root, hdr, tr); entryErr != nil {
			return entryErr
		}
	}
}

// extractEntry writes a single tar entry into root.
func extractEntry(root *os.Root, hdr *tar.Header, tr io.Reader) error {
	mode := hdr.FileInfo().Mode().Perm()
	// Tar directory entries carry a trailing separator, which os.Root
	// rejects since the go1.26.5 trailing-slash traversal fix (GO-2026-4970).
	name := filepath.Clean(hdr.Name)

	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := root.MkdirAll(name, mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", name, err)
		}
	case tar.TypeReg:
		if err := extractRegularFile(root, name, tr, hdr.Size, mode); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if err := extractSymlink(root, name, hdr.Linkname); err != nil {
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
