package executor

import (
    "fmt"
    "os"
    "os/exec"
    "strings"

    "github.com/istr/strike/pipeline"
)

type Run struct {
    Step        *pipeline.Step
    InputMounts []Mount
    SourceMounts []Mount
    OutputDir   string
    Secrets     map[string]string // env-name -> plaintext
}

type Mount struct {
    Host      string
    Container string
    ReadOnly  bool
}

func (r Run) Execute() error {
    args := []string{"run", "--rm", "--network=none", "--device", "/dev/fuse"}

    for _, m := range r.InputMounts {
        flag := fmt.Sprintf("%s:%s", m.Host, m.Container)
        if m.ReadOnly {
            flag += ":ro"
        }
        args = append(args, "-v", flag)
    }

    for _, m := range r.SourceMounts {
        args = append(args, "-v",
            fmt.Sprintf("%s:%s:ro", m.Host, m.Container))
    }

    // Output directory
    args = append(args, "-v", r.OutputDir+":/out")

    // Pass secret env names only - values via process environment,
    // never written to args (no ps aux leak)
    for envName, val := range r.Secrets {
        args = append(args, "--env", envName)
        os.Setenv(envName, val)
    }

    args = append(args, r.Step.Image)
    args = append(args, r.Step.Args...)

    cmd := exec.Command("podman", args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

// LoadOCITar loads an OCI tar archive into the local container store
// and returns the manifest digest.
func LoadOCITar(tarPath string) (string, error) {
    cmd := exec.Command("podman", "load", "-i", tarPath, "--quiet")
    out, err := cmd.Output()
    if err != nil {
        return "", fmt.Errorf("podman load: %w", err)
    }

    imageID := strings.TrimSpace(string(out))
    return InspectDigest(imageID)
}

// InspectDigest returns the manifest digest of a local image.
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
