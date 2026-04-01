package registry

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ExistsLocal checks if an image exists in the local container store (no network).
func ExistsLocal(tag string) bool {
	err := exec.Command("podman", "image", "exists", tag).Run()
	return err == nil
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
func Pull(tag string) error {
	return exec.Command("podman", "pull", tag).Run()
}

// PushArtifact pushes a local directory or file as an OCI image to the registry.
func PushArtifact(localPath, tag string) error {
	return exec.Command("podman", "push", tag).Run()
}

// CopyImage copies an image between registries using go-containerregistry.
func CopyImage(src, dst string) error {
	if err := crane.Copy(src, dst,
		crane.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return fmt.Errorf("copy %s → %s: %w", src, dst, err)
	}
	return nil
}

// LoadOCITar loads a single-image OCI tar archive into the local container
// store and returns the manifest digest.
func LoadOCITar(tarPath string) (string, error) {
	cmd := exec.Command("podman", "load", "-i", tarPath, "--quiet")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("podman load: %w", err)
	}

	imageID := strings.TrimSpace(string(out))
	return InspectDigest(imageID)
}

// LoadOCITarByDigest loads a specific image from a multi-manifest OCI tar
// archive into the local container store, selecting it by digest.
func LoadOCITarByDigest(tarPath, digest string) error {
	localTag := "localhost/strike:" + strings.TrimPrefix(digest, "sha256:")[:12]

	cmd := exec.Command("podman", "load", "-i", tarPath, "--quiet")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("podman load: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Tag the loaded image with our local tag for downstream reference
	cmd = exec.Command("podman", "tag", digest, localTag)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("podman tag %s → %s: %s: %w",
			digest, localTag, strings.TrimSpace(string(out)), err)
	}

	return nil
}

// InspectDigest returns the manifest digest of a local image via podman.
func InspectDigest(imageRef string) (string, error) {
	cmd := exec.Command("podman", "inspect", "--format", "{{.Digest}}", imageRef)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("podman inspect %q: %w", imageRef, err)
	}

	digest := strings.TrimSpace(string(out))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("unexpected digest format for %q: %q", imageRef, digest)
	}
	return digest, nil
}

// Find implements local-first lookup with remote fallback.
func Find(tag string) (bool, bool) {
	if ExistsLocal(tag) {
		return true, false
	}
	if ExistsRemote(tag) {
		return false, true
	}
	return false, false
}
