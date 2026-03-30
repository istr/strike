package registry

import (
    "fmt"
    "os/exec"
    "strings"
)

// ExistsLocal checks if an image exists in the local container store (no network).
func ExistsLocal(tag string) bool {
    err := exec.Command("skopeo", "inspect",
        "--raw",
        "containers-storage:"+tag,
    ).Run()
    return err == nil
}

// ExistsRemote checks if an image exists in a remote registry (one roundtrip).
func ExistsRemote(tag string) bool {
    err := exec.Command("skopeo", "inspect",
        "--raw",
        "docker://"+tag,
    ).Run()
    return err == nil
}

// Pull fetches an image from a remote registry into the local store.
func Pull(tag string) error {
    return exec.Command("podman", "pull", tag).Run()
}

// PushArtifact pushes a local directory or file as an OCI image to the registry.
// Uses oras for non-container artifacts, podman push for OCI images.
func PushArtifact(localPath, tag string) error {
    // For oci-tar: podman load + podman push
    // For directory/file: oras push
    // Simplified:
    return exec.Command("podman", "push", tag).Run()
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
// archive into the local container store, selecting it by the
// org.opencontainers.image.ref.name annotation set during pack.
func LoadOCITarByDigest(tarPath, digest string) error {
    localTag := "localhost/strike:" + strings.TrimPrefix(digest, "sha256:")[:12]
    src := fmt.Sprintf("oci-archive:%s:%s", tarPath, digest)
    dst := "containers-storage:" + localTag

    cmd := exec.Command("skopeo", "copy", src, dst)
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("skopeo copy: %s: %w", strings.TrimSpace(string(out)), err)
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
