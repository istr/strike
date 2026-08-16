package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

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
