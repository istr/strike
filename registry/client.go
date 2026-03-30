package registry

import (
    "os/exec"
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
