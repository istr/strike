package registry

import (
    "crypto/sha256"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sort"

    "github.com/istr/strike/lane"
)

// SpecHash computes the spec hash of a step (Merkle tree over the DAG).
// Inputs are the spec hashes of producing steps, not their contents -
// fully computable before execution.
func SpecHash(
    step *lane.Step,
    imageDigest string,                    // sha256 digest of the image
    inputHashes map[string]string,         // step-name -> spec hash of producing step
    sourceHashes map[string]string,        // mount-path -> sha256 of source file
) string {
    h := sha256.New()

    h.Write([]byte(imageDigest))

    args := append([]string{}, step.Args...)
    sort.Strings(args)
    for _, a := range args {
        h.Write([]byte(a))
    }

    // Input hashes sorted by name for determinism
    names := sortedKeys(inputHashes)
    for _, n := range names {
        h.Write([]byte(n + "=" + inputHashes[n]))
    }

    // Source hashes sorted by path
    paths := sortedKeys(sourceHashes)
    for _, p := range paths {
        h.Write([]byte(p + "=" + sourceHashes[p]))
    }

    return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// Tag builds the registry tag from step name and hash.
// Format: registry:step-name-hash16
// Example: ghcr.io/istr/strike-cache:build-package-a3f9c2b1d4e7f801
func Tag(registry, stepName, hash string) string {
    return fmt.Sprintf("%s:%s-%s", registry, stepName, hash)
}

// HashFile computes SHA256 of a source file.
func HashFile(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", err
    }
    return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// HashDir computes SHA256 of all files in a directory (recursive, sorted).
func HashDir(dir string) (string, error) {
    h := sha256.New()
    err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
        if err != nil || d.IsDir() {
            return err
        }
        content, err := os.ReadFile(path)
        if err != nil {
            return err
        }
        h.Write([]byte(path))
        h.Write(content)
        return nil
    })
    return fmt.Sprintf("%x", h.Sum(nil)), err
}

func sortedKeys(m map[string]string) []string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    return keys
}
