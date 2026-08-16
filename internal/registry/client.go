package registry

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
)

// Client wraps container engine operations for registry interaction.
type Client struct {
	Engine container.Engine
}

// ociLayoutMarker is the oci-layout marker file every OCI image layout
// carries, byte-identical to the one go-containerregistry writes.
const ociLayoutMarker = `{
    "imageLayoutVersion": "1.0.0"
}`

// OCITarFromImage serializes img as an OCI image layout tar, the format the
// engine image load accepts. The manifest, the config, and every layer blob
// are written straight from memory, so no payload reaches the controller host
// filesystem (ADR-035). The index carries exactly one manifest descriptor
// (ADR-046); annotations, when given, are set on that descriptor. Entry
// mtimes are left zero, so one image always serializes to the same bytes.
func OCITarFromImage(img v1.Image, annotations map[string]string) ([]byte, error) {
	desc, err := partial.Descriptor(img)
	if err != nil {
		return nil, fmt.Errorf("layout: describe image: %w", err)
	}
	if len(annotations) > 0 {
		desc.Annotations = annotations
	}
	index, err := json.MarshalIndent(v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{*desc},
	}, "", "   ")
	if err != nil {
		return nil, fmt.Errorf("layout: marshal index: %w", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if blobErr := writeLayoutBlobs(tw, img, *desc); blobErr != nil {
		return nil, blobErr
	}
	if fErr := writeLayoutEntry(tw, "index.json", index); fErr != nil {
		return nil, fErr
	}
	if fErr := writeLayoutEntry(tw, "oci-layout", []byte(ociLayoutMarker)); fErr != nil {
		return nil, fErr
	}
	if closeErr := tw.Close(); closeErr != nil {
		return nil, fmt.Errorf("layout: close tar: %w", closeErr)
	}
	return buf.Bytes(), nil
}

// writeLayoutBlobs writes the blobs tree of an OCI layout: the manifest, the
// config, and every layer, each at blobs/<algorithm>/<hex>. One algorithm
// directory suffices because every digest strike produces or consumes is
// sha256 (ADR-008).
func writeLayoutBlobs(tw *tar.Writer, img v1.Image, desc v1.Descriptor) error {
	for _, dir := range []string{"blobs/", "blobs/" + desc.Digest.Algorithm + "/"} {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     dir,
			Mode:     0o755,
		}); err != nil {
			return fmt.Errorf("layout: write %s: %w", dir, err)
		}
	}

	manifest, err := img.RawManifest()
	if err != nil {
		return fmt.Errorf("layout: raw manifest: %w", err)
	}
	if wErr := writeLayoutEntry(tw, blobName(desc.Digest), manifest); wErr != nil {
		return wErr
	}

	configHash, err := img.ConfigName()
	if err != nil {
		return fmt.Errorf("layout: config digest: %w", err)
	}
	config, err := img.RawConfigFile()
	if err != nil {
		return fmt.Errorf("layout: raw config: %w", err)
	}
	if wErr := writeLayoutEntry(tw, blobName(configHash), config); wErr != nil {
		return wErr
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("layout: layers: %w", err)
	}
	for _, layer := range layers {
		if wErr := writeLayerBlob(tw, layer); wErr != nil {
			return wErr
		}
	}
	return nil
}

// writeLayerBlob streams one layer's compressed blob into the layout tar
// without buffering a second copy of it.
func writeLayerBlob(tw *tar.Writer, layer v1.Layer) error {
	digest, err := layer.Digest()
	if err != nil {
		return fmt.Errorf("layout: layer digest: %w", err)
	}
	size, err := layer.Size()
	if err != nil {
		return fmt.Errorf("layout: layer %s size: %w", digest, err)
	}
	rc, err := layer.Compressed()
	if err != nil {
		return fmt.Errorf("layout: open layer %s: %w", digest, err)
	}
	writeErr := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     blobName(digest),
		Size:     size,
		Mode:     0o644,
	})
	if writeErr == nil {
		_, writeErr = io.Copy(tw, rc)
	}
	if closeErr := rc.Close(); closeErr != nil {
		return fmt.Errorf("layout: close layer %s: %w", digest, closeErr)
	}
	if writeErr != nil {
		return fmt.Errorf("layout: write layer %s: %w", digest, writeErr)
	}
	return nil
}

// writeLayoutEntry writes one whole in-memory file into the layout tar.
func writeLayoutEntry(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     int64(len(data)),
		Mode:     0o644,
	}); err != nil {
		return fmt.Errorf("layout: write %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("layout: write %s: %w", name, err)
	}
	return nil
}

// blobName is the layout path a blob digest addresses.
func blobName(h v1.Hash) string {
	return "blobs/" + h.Algorithm + "/" + h.Hex
}

// InspectDigest returns the manifest digest of a local image.
func (c *Client) InspectDigest(ctx context.Context, ref string) (primitive.Digest, error) {
	info, err := c.Engine.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	if info.Digest == "" {
		return "", fmt.Errorf("no digest for %s", ref)
	}
	return primitive.ParseDigest(info.Digest)
}
