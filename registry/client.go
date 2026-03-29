package registry

import (
    "os/exec"
)

// ExistsLocal prüft ob ein Image im lokalen Container Store liegt — kein Netzwerk
func ExistsLocal(tag string) bool {
    err := exec.Command("skopeo", "inspect",
        "--raw",
        "containers-storage:"+tag,
    ).Run()
    return err == nil
}

// ExistsRemote prüft ob ein Image in der Remote-Registry existiert — ein Roundtrip
func ExistsRemote(tag string) bool {
    err := exec.Command("skopeo", "inspect",
        "--raw",
        "docker://"+tag,
    ).Run()
    return err == nil
}

// Pull holt ein Image vom Remote in den lokalen Store
func Pull(tag string) error {
    return exec.Command("podman", "pull", tag).Run()
}

// PushArtifact pushed ein lokales Verzeichnis oder File als OCI-Image in die Registry.
// Nutzt oras für nicht-container Artefakte, podman push für OCI-Images.
func PushArtifact(localPath, tag string) error {
    // für oci-tar: podman load + podman push
    // für directory/file: oras push
    // hier vereinfacht:
    return exec.Command("podman", "push", tag).Run()
}

// Find implementiert Local-first mit Remote-Fallback
func Find(tag string) (bool, bool) {
    if ExistsLocal(tag) {
        return true, false   // local=true, remote=false
    }
    if ExistsRemote(tag) {
        return false, true   // local=false, remote=true
    }
    return false, false
}
