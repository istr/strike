package registry

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

// Client wraps container engine operations for registry interaction.
type Client struct {
	Engine container.Engine
}

// ExistsLocal checks if an image exists in the local container store.
func (c *Client) ExistsLocal(ctx context.Context, tag string) bool {
	exists, err := c.Engine.ImageExists(ctx, tag)
	if err != nil {
		return false
	}
	return exists
}

// ExistsRemote checks if an image exists in a remote registry (one roundtrip).
func ExistsRemote(tag string) bool {
	ref, err := name.ParseReference(tag)
	if err != nil {
		return false
	}
	_, err = remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	return err == nil
}

// Pull fetches an image from a remote registry into the local store.
func (c *Client) Pull(ctx context.Context, tag string) error {
	return c.Engine.ImagePull(ctx, tag)
}

// PushArtifact pushes a local image to the registry.
func (c *Client) PushArtifact(ctx context.Context, tag string) error {
	return c.Engine.ImagePush(ctx, tag)
}

// CopyImage copies an image between registries using go-containerregistry.
func CopyImage(src, dst string) error {
	if err := crane.Copy(src, dst,
		crane.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return nil
}

// LoadOCITar loads the main image from an OCI tar archive into the local
// container store and returns the manifest digest. Multi-image archives
// (e.g. from Pack, which includes SBOM and signature artifacts) are handled
// by extracting the annotated main image into a single-image layout before
// loading into the engine. The loaded image is tagged locally so it can be
// referenced by digest in subsequent operations.
func (c *Client) LoadOCITar(ctx context.Context, root *os.Root, relPath string) (digest lane.Digest, err error) {
	r, openErr := openMainImage(root, relPath)
	if openErr != nil {
		return "", fmt.Errorf("image load: %w", openErr)
	}

	id, err := c.Engine.ImageLoad(ctx, r)
	if err != nil {
		return "", err
	}

	d, err := c.InspectDigest(ctx, id)
	if err != nil {
		return "", err
	}

	// Tag with a local reference so downstream operations can look up by digest.
	localTag := "localhost/strike:" + strings.TrimPrefix(string(d), "sha256:")[:12]
	if tagErr := c.Engine.ImageTag(ctx, id, localTag); tagErr != nil {
		return "", fmt.Errorf("image tag: %w", tagErr)
	}

	return d, nil
}

// LoadOCITarByDigest loads the main image from an OCI tar archive into the
// local container store and tags it for downstream reference.
func (c *Client) LoadOCITarByDigest(ctx context.Context, root *os.Root, relPath string, digest lane.Digest) (err error) {
	r, openErr := openMainImage(root, relPath)
	if openErr != nil {
		return fmt.Errorf("image load: %w", openErr)
	}

	id, loadErr := c.Engine.ImageLoad(ctx, r)
	if loadErr != nil {
		return loadErr
	}

	localTag := "localhost/strike:" + strings.TrimPrefix(string(digest), "sha256:")[:12]
	return c.Engine.ImageTag(ctx, id, localTag)
}

// openMainImage extracts the main image from an OCI layout tar archive
// and returns a reader for a single-image OCI tar suitable for podman load.
// If the archive contains only one image, it is returned as-is via a reader
// over the original tar. For multi-image archives, the image annotated with
// org.opencontainers.image.ref.name is extracted.
func openMainImage(root *os.Root, relPath string) (io.Reader, error) {
	// Extract tar to temp dir so layout.Path can read the index.
	f, err := root.Open(relPath)
	if err != nil {
		return nil, err
	}
	defer warnClose(f, "registry load")

	tmpDir, err := os.MkdirTemp("", "strike-load-")
	if err != nil {
		return nil, err
	}
	// Caller only needs the returned reader; clean up the temp dir after.
	// The tar bytes are buffered in memory, so the dir can be removed now.
	defer warnRemoveAll(tmpDir, "registry load")

	if extractErr := extractTar(f, tmpDir); extractErr != nil {
		return nil, fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest: %w", err)
	}

	// Single image — pass through directly.
	if len(manifest.Manifests) == 1 {
		desc := manifest.Manifests[0]
		img, imgErr := idx.Image(desc.Digest)
		if imgErr != nil {
			return nil, imgErr
		}
		return singleImageTar(img, desc.Annotations)
	}

	// Multi-image — find the main image by annotation.
	for _, desc := range manifest.Manifests {
		if _, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
			img, imgErr := idx.Image(desc.Digest)
			if imgErr != nil {
				return nil, imgErr
			}
			return singleImageTar(img, desc.Annotations)
		}
	}

	return nil, fmt.Errorf("no annotated main image in %d-manifest archive", len(manifest.Manifests))
}

// singleImageTar writes a single OCI image as a layout tar into an in-memory
// buffer and returns a reader over it.
func singleImageTar(img v1.Image, annotations map[string]string) (io.Reader, error) {
	tmpDir, err := os.MkdirTemp("", "strike-single-")
	if err != nil {
		return nil, err
	}
	defer warnRemoveAll(tmpDir, "registry single image")

	lp, err := layout.Write(tmpDir, empty.Index)
	if err != nil {
		return nil, fmt.Errorf("write single layout: %w", err)
	}
	var opts []layout.Option
	if len(annotations) > 0 {
		opts = append(opts, layout.WithAnnotations(annotations))
	}
	if err := lp.AppendImage(img, opts...); err != nil {
		return nil, fmt.Errorf("append image: %w", err)
	}

	var buf bytes.Buffer
	if err := tarDirectory(tmpDir, &buf); err != nil {
		return nil, fmt.Errorf("tar single layout: %w", err)
	}
	return &buf, nil
}

// extractTar extracts a tar archive into dst.
func extractTar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := dst + "/" + hdr.Name
		switch hdr.Typeflag {
		case tar.TypeDir:
			if mkErr := os.MkdirAll(target, 0o750); mkErr != nil {
				return mkErr
			}
		case tar.TypeReg:
			if writeErr := extractFile(tr, target); writeErr != nil {
				return writeErr
			}
		}
	}
}

// extractFile writes a single tar entry to the filesystem.
func extractFile(tr *tar.Reader, target string) error {
	if mkErr := os.MkdirAll(target[:strings.LastIndex(target, "/")], 0o750); mkErr != nil {
		return mkErr
	}
	out, err := os.Create(target) //nolint:gosec // G304: target is inside MkdirTemp dir, not user input
	if err != nil {
		return err
	}
	if _, cpErr := io.Copy(out, tr); cpErr != nil {
		warnClose(out, "registry extract file")
		return cpErr
	}
	return out.Close()
}

// tarDirectory writes the contents of dir as a tar archive to w.
func tarDirectory(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer warnClose(tw, "registry tar")

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	return tarDirEntries(tw, dir, "", entries)
}

// tarDirEntries recursively writes directory entries to a tar writer.
func tarDirEntries(tw *tar.Writer, base, prefix string, entries []os.DirEntry) error {
	for _, e := range entries {
		rel := prefix + e.Name()
		full := base + "/" + rel
		info, infoErr := e.Info()
		if infoErr != nil {
			return infoErr
		}
		hdr, hdrErr := tar.FileInfoHeader(info, "")
		if hdrErr != nil {
			return hdrErr
		}
		hdr.Name = rel
		if twErr := tw.WriteHeader(hdr); twErr != nil {
			return twErr
		}
		if e.IsDir() {
			sub, rdErr := os.ReadDir(full)
			if rdErr != nil {
				return rdErr
			}
			if err := tarDirEntries(tw, base, rel+"/", sub); err != nil {
				return err
			}
			continue
		}
		data, rdErr := os.ReadFile(full) //nolint:gosec // G304: full is inside MkdirTemp dir, not user input
		if rdErr != nil {
			return rdErr
		}
		if _, wErr := tw.Write(data); wErr != nil {
			return wErr
		}
	}
	return nil
}

// InspectDigest returns the manifest digest of a local image.
func (c *Client) InspectDigest(ctx context.Context, ref string) (lane.Digest, error) {
	info, err := c.Engine.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	if info.Digest == "" {
		return "", fmt.Errorf("no digest for %s", ref)
	}
	return lane.Digest(info.Digest), nil
}

// InspectAnnotation retrieves an annotation value from a local image.
func (c *Client) InspectAnnotation(ctx context.Context, tag, annotation string) (string, error) {
	info, err := c.Engine.ImageInspect(ctx, tag)
	if err != nil {
		return "", err
	}
	return info.Annotations[annotation], nil
}

// Find implements local-first lookup with remote fallback.
func (c *Client) Find(ctx context.Context, tag string) (bool, bool) {
	if c.ExistsLocal(ctx, tag) {
		return true, false
	}
	if ExistsRemote(tag) {
		return false, true
	}
	return false, false
}
