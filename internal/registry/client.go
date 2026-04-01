package registry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/istr/strike/internal/container"
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

// LoadOCITar loads a single-image OCI tar archive into the local container
// store and returns the manifest digest.
func (c *Client) LoadOCITar(ctx context.Context, tarPath string) (digest string, err error) {
	f, err := os.Open(tarPath) //nolint:gosec // G304: OCI tar path from step output
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	id, err := c.Engine.ImageLoad(ctx, f)
	if err != nil {
		return "", err
	}

	return c.InspectDigest(ctx, id)
}

// LoadOCITarByDigest loads an image from an OCI tar archive into the local
// container store, selecting it by digest, and tags it for downstream reference.
func (c *Client) LoadOCITarByDigest(ctx context.Context, tarPath, digest string) (err error) {
	f, err := os.Open(tarPath) //nolint:gosec // G304: OCI tar path from step output
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	id, err := c.Engine.ImageLoad(ctx, f)
	if err != nil {
		return err
	}

	localTag := "localhost/strike:" + strings.TrimPrefix(digest, "sha256:")[:12]
	return c.Engine.ImageTag(ctx, id, localTag)
}

// InspectDigest returns the manifest digest of a local image.
func (c *Client) InspectDigest(ctx context.Context, ref string) (string, error) {
	info, err := c.Engine.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	if info.Digest == "" {
		return "", fmt.Errorf("no digest for %s", ref)
	}
	return info.Digest, nil
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
