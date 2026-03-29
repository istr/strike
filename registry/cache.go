package registry

import (
    "crypto/sha256"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sort"

    "github.com/istr/strike/pipeline"
)

// SpecHash berechnet den Spec-Hash eines Steps (Merkle-Tree über DAG).
// Inputs sind die SpecHashes der produzierenden Steps, nicht deren Inhalte —
// vollständig berechenbar vor der Ausführung.
func SpecHash(
    step *pipeline.Step,
    imageDigest string,                    // sha256-Digest des Images
    inputHashes map[string]string,         // step-name → spec-hash des produzierenden steps
    sourceHashes map[string]string,        // mount-pfad → sha256 der Quelldatei
) string {
    h := sha256.New()

    h.Write([]byte(imageDigest))

    args := append([]string{}, step.Args...)
    sort.Strings(args)
    for _, a := range args {
        h.Write([]byte(a))
    }

    // Input-Hashes sortiert nach Name für Determinismus
    names := sortedKeys(inputHashes)
    for _, n := range names {
        h.Write([]byte(n + "=" + inputHashes[n]))
    }

    // Source-Hashes sortiert nach Pfad
    paths := sortedKeys(sourceHashes)
    for _, p := range paths {
        h.Write([]byte(p + "=" + sourceHashes[p]))
    }

    return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// Tag bildet den Registry-Tag aus Step-Name und Hash.
// Format: registry:step-name-hash16
// Beispiel: ghcr.io/ingo-struck/cache:build-package-a3f9c2b1d4e7f801
func Tag(registry, stepName, hash string) string {
    return fmt.Sprintf("%s:%s-%s", registry, stepName, hash)
}

// HashFile berechnet SHA256 einer Quelldatei
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

// HashDir berechnet SHA256 aller Dateien in einem Verzeichnis (rekursiv, sortiert)
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
