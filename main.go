package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/istr/strike/executor"
    "github.com/istr/strike/lane"
    "github.com/istr/strike/registry"
)

const usage = `strike - reproducible, rootless CI/CD lanes

Usage:
  strike run      [lane.yaml]   Run a lane
  strike validate [lane.yaml]   Validate without running
  strike dag      [lane.yaml]   Show DAG and exit
  strike compare  <file1> <file2> <output>   Compare two files by SHA-256

Default file: lane.yaml in the current directory
`

func main() {
    log.SetFlags(0)

    if len(os.Args) < 2 {
        fmt.Print(usage)
        os.Exit(1)
    }

    // compare has its own arg layout
    if os.Args[1] == "compare" {
        if len(os.Args) != 5 {
            log.Fatal("usage: strike compare <file1> <file2> <output>")
        }
        cmdCompare(os.Args[2], os.Args[3], os.Args[4])
        return
    }

    laneFile := "lane.yaml"
    if len(os.Args) >= 3 {
        laneFile = os.Args[2]
    }

    switch os.Args[1] {
    case "validate":
        cmdValidate(laneFile)
    case "dag":
        cmdDAG(laneFile)
    case "run":
        cmdRun(laneFile)
    default:
        fmt.Print(usage)
        os.Exit(1)
    }
}

// --- validate ---------------------------------------------------------------

func cmdValidate(path string) {
    p, err := lane.Parse(path)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
    if _, err := lane.Build(p); err != nil {
        log.Fatalf("error: DAG: %v", err)
    }
    fmt.Printf("ok: %s is valid (%d steps)\n", path, len(p.Steps))
}

// --- dag --------------------------------------------------------------------

func cmdDAG(path string) {
    p, err := lane.Parse(path)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
    dag, err := lane.Build(p)
    if err != nil {
        log.Fatalf("error: %v", err)
    }

    fmt.Println("Execution order:")
    for i, name := range dag.Order {
        step := dag.Steps[name]
        deps := []string{}
        for _, inp := range step.Inputs {
            deps = append(deps, inp.From)
        }
        if len(deps) > 0 {
            fmt.Printf("  %d. %s <- %v\n", i+1, name, deps)
        } else {
            fmt.Printf("  %d. %s\n", i+1, name)
        }
    }

    fmt.Println("\nDependency graph:")
    fmt.Print(dag.Tree())
}

// --- run --------------------------------------------------------------------

func cmdRun(path string) {
    p, err := lane.Parse(path)
    if err != nil {
        log.Fatalf("error: %v", err)
    }
    dag, err := lane.Build(p)
    if err != nil {
        log.Fatalf("error: %v", err)
    }

    // Collected spec hashes per step for downstream cache keys
    specHashes := map[string]string{}
    // Collected output directories per step
    outputDirs := map[string]string{}
    // Manifest digests of loaded OCI tar outputs: step/output -> "sha256:..."
    ociDigests := map[string]string{}

    for _, stepName := range dag.Order {
        step := dag.Steps[stepName]

        // Resolve image digest: from pinned ref or from a previous step
        var imageDigest string
        if step.ImageFrom != nil {
            key := step.ImageFrom.Step + "/" + step.ImageFrom.Output
            digest, ok := ociDigests[key]
            if !ok {
                log.Fatalf("error: %s: image_from %s/%s: digest not available",
                    stepName, step.ImageFrom.Step, step.ImageFrom.Output)
            }
            imageDigest = digest
            // Set image so executor uses the loaded image by digest
            step.Image = step.ImageFrom.Step + "-" + step.ImageFrom.Output + "@" + digest
        } else {
            var err error
            imageDigest, err = resolveDigest(step.Image)
            if err != nil {
                log.Fatalf("error: %s: image digest: %v", stepName, err)
            }
        }

        // Input hashes from previous spec hashes
        inputHashes := map[string]string{}
        for _, inp := range step.Inputs {
            inputHashes[inp.Name] = specHashes[inp.From]
        }

        // Source hashes
        sourceHashes := map[string]string{}
        for _, src := range step.Sources {
            h, err := registry.HashPath(src.Path)
            if err != nil {
                log.Fatalf("error: %s: source hash %s: %v", stepName, src.Path, err)
            }
            sourceHashes[src.Mount] = h
        }

        key := registry.SpecHash(step, imageDigest, inputHashes, sourceHashes)
        tag := registry.Tag(p.Registry, stepName, key)
        specHashes[stepName] = key

        // Cache check: local first, then remote
        local, remote := registry.Find(tag)
        switch {
        case local:
            fmt.Printf("CACHED %s (local: %s)\n", stepName, tag)
            outputDirs[stepName] = cachedOutputDir(tag)
            continue
        case remote:
            fmt.Printf("PULL   %s (remote: %s)\n", stepName, tag)
            if err := registry.Pull(tag); err != nil {
                log.Fatalf("error: %s: pull failed: %v", stepName, err)
            }
            outputDirs[stepName] = cachedOutputDir(tag)
            continue
        }

        // Execute
        fmt.Printf("RUN    %s\n", stepName)

        outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
        if err != nil {
            log.Fatal(err)
        }

        // Resolve secrets
        secrets, err := resolveSecrets(step.Secrets, p.Secrets)
        if err != nil {
            log.Fatalf("error: %s: secrets: %v", stepName, err)
        }

        // Input mounts from previous output directories
        inputMounts := []executor.Mount{}
        for _, inp := range step.Inputs {
            // Resolve the output path from the producing step
            fromStep := dag.Steps[inp.From]
            var hostPath string
            for _, out := range fromStep.Outputs {
                if out.Name == inp.Name {
                    hostPath = filepath.Join(outputDirs[inp.From], filepath.Base(out.Path))
                    break
                }
            }
            if hostPath == "" {
                log.Fatalf("error: %s: input %q not found in outputs of %q", stepName, inp.Name, inp.From)
            }
            inputMounts = append(inputMounts, executor.Mount{
                Host:      hostPath,
                Container: inp.Mount,
                ReadOnly:  true,
            })
        }

        // Source mounts
        sourceMounts := []executor.Mount{}
        for _, src := range step.Sources {
            sourceMounts = append(sourceMounts, executor.Mount{
                Host:      src.Path,
                Container: src.Mount,
                ReadOnly:  true,
            })
        }

        run := executor.Run{
            Step:         step,
            InputMounts:  inputMounts,
            SourceMounts: sourceMounts,
            OutputDir:    outDir,
            Secrets:      secrets,
        }
        if err := run.Execute(); err != nil {
            log.Fatalf("error: %s: execution failed: %v", stepName, err)
        }

        outputDirs[stepName] = outDir

        // Load OCI tar outputs and extract digests
        for _, out := range step.Outputs {
            if out.Type != "oci-tar" {
                continue
            }
            tarPath := filepath.Join(outDir, filepath.Base(out.Path))
            digest, err := executor.LoadOCITar(tarPath)
            if err != nil {
                log.Fatalf("error: %s: oci-tar load %q: %v", stepName, out.Name, err)
            }
            key := stepName + "/" + out.Name
            ociDigests[key] = digest
            fmt.Printf("       %s/%s -> %s\n", stepName, out.Name, digest)
        }

        // Push OCI artifacts to registry cache
        pushed := false
        for _, out := range step.Outputs {
            if out.Type == "oci-tar" {
                if err := registry.PushArtifact(outDir, tag); err != nil {
                    log.Fatalf("error: %s: push failed: %v", stepName, err)
                }
                pushed = true
                break
            }
        }
        if pushed {
            fmt.Printf("OK     %s -> %s\n", stepName, tag)
        } else {
            fmt.Printf("OK     %s\n", stepName)
        }
    }
}

// --- compare ----------------------------------------------------------------

func cmdCompare(file1, file2, output string) {
    h1, err := registry.HashFile(file1)
    if err != nil {
        log.Fatalf("error: %s: %v", file1, err)
    }
    h2, err := registry.HashFile(file2)
    if err != nil {
        log.Fatalf("error: %s: %v", file2, err)
    }
    if h1 != h2 {
        log.Fatalf("error: files differ\n  %s: %s\n  %s: %s", file1, h1, file2, h2)
    }
    if err := os.WriteFile(output, []byte(h1+"\n"), 0644); err != nil {
        log.Fatalf("error: write %s: %v", output, err)
    }
    fmt.Printf("ok: %s\n", h1)
}

// --- helpers ----------------------------------------------------------------

func resolveDigest(imageRef string) (string, error) {
    // Image ref already contains @sha256: - extract the digest
    for i, c := range imageRef {
        if c == '@' {
            return imageRef[i+1:], nil
        }
    }

    // Local image without digest (e.g. bootstrap root) - resolve via podman inspect
    return executor.InspectDigest(imageRef)
}

func cachedOutputDir(tag string) string {
    // Local output mounted from container store
    // (simplified - in practice: skopeo copy containers-storage -> local dir)
    return "/tmp/strike-cache/" + sanitize(tag)
}

func resolveSecrets(
    refs []lane.SecretRef,
    sources map[string]lane.SecretSource,
) (map[string]string, error) {
    result := map[string]string{}
    for _, ref := range refs {
        source, ok := sources[ref.Name]
        if !ok {
            return nil, fmt.Errorf("secret %q not defined in lane.secrets", ref.Name)
        }
        val, err := readSecret(string(source))
        if err != nil {
            return nil, fmt.Errorf("secret %q: %w", ref.Name, err)
        }
        result[ref.Env] = val
    }
    return result, nil
}

func readSecret(source string) (string, error) {
    switch {
    case len(source) > 6 && source[:6] == "env://":
        val := os.Getenv(source[6:])
        if val == "" {
            return "", fmt.Errorf("env variable %q not set", source[6:])
        }
        return val, nil
    case len(source) > 7 && source[:7] == "file://":
        data, err := os.ReadFile(source[7:])
        return string(data), err
    default:
        return "", fmt.Errorf("unknown secret source: %q (supported: env://, file://)", source)
    }
}

func sanitize(s string) string {
    result := make([]byte, len(s))
    for i, c := range []byte(s) {
        if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
            result[i] = c
        } else {
            result[i] = '-'
        }
    }
    return string(result)
}
