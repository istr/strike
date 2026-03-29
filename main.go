package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/istr/strike/executor"
    "github.com/istr/strike/pipeline"
    "github.com/istr/strike/registry"
)

const usage = `strike — reproduzierbare, rootless CI/CD-Pipelines

Verwendung:
  strike run      [pipeline.yaml]   Pipeline ausführen
  strike validate [pipeline.yaml]   Pipeline validieren ohne Ausführung
  strike dag      [pipeline.yaml]   DAG anzeigen und beenden

Standarddatei: pipeline.yaml im aktuellen Verzeichnis
`

func main() {
    log.SetFlags(0) // kein Timestamp in Fehlermeldungen

    if len(os.Args) < 2 {
        fmt.Print(usage)
        os.Exit(1)
    }

    pipelineFile := "pipeline.yaml"
    if len(os.Args) >= 3 {
        pipelineFile = os.Args[2]
    }

    switch os.Args[1] {
    case "validate":
        cmdValidate(pipelineFile)
    case "dag":
        cmdDAG(pipelineFile)
    case "run":
        cmdRun(pipelineFile)
    default:
        fmt.Print(usage)
        os.Exit(1)
    }
}

// --- validate ---------------------------------------------------------------

func cmdValidate(path string) {
    p, err := pipeline.Parse(path)
    if err != nil {
        log.Fatalf("❌ %v", err)
    }
    if _, err := pipeline.Build(p); err != nil {
        log.Fatalf("❌ DAG: %v", err)
    }
    fmt.Printf("✅ %s ist gültig (%d steps)\n", path, len(p.Steps))
}

// --- dag --------------------------------------------------------------------

func cmdDAG(path string) {
    p, err := pipeline.Parse(path)
    if err != nil {
        log.Fatalf("❌ %v", err)
    }
    dag, err := pipeline.Build(p)
    if err != nil {
        log.Fatalf("❌ %v", err)
    }

    fmt.Println("Ausführungsreihenfolge:")
    for i, name := range dag.Order {
        step := dag.Steps[name]
        deps := []string{}
        for _, inp := range step.Inputs {
            deps = append(deps, inp.From)
        }
        if len(deps) > 0 {
            fmt.Printf("  %d. %s ← %v\n", i+1, name, deps)
        } else {
            fmt.Printf("  %d. %s\n", i+1, name)
        }
    }

    fmt.Println("\nDependency graph:")
    fmt.Print(dag.Tree());
}

// --- run --------------------------------------------------------------------

func cmdRun(path string) {
    p, err := pipeline.Parse(path)
    if err != nil {
        log.Fatalf("❌ %v", err)
    }
    dag, err := pipeline.Build(p)
    if err != nil {
        log.Fatalf("❌ %v", err)
    }

    // Gesammelte Spec-Hashes pro Step — für nachfolgende Cache-Keys
    specHashes := map[string]string{}
    // Gesammelte Output-Verzeichnisse pro Step
    outputDirs := map[string]string{}

    for _, stepName := range dag.Order {
        step := dag.Steps[stepName]

        // Image-Digest auflösen (einmalig pro Step)
        imageDigest, err := resolveDigest(string(step.Image))
        if err != nil {
            log.Fatalf("❌ %s: image digest: %v", stepName, err)
        }

        // Input-Hashes aus vorherigen Spec-Hashes
        inputHashes := map[string]string{}
        for _, inp := range step.Inputs {
            inputHashes[inp.Name] = specHashes[inp.From]
        }

        // Source-Hashes
        sourceHashes := map[string]string{}
        for _, src := range step.Sources {
            h, err := registry.HashFile(src.Path)
            if err != nil {
                log.Fatalf("❌ %s: source hash %s: %v", stepName, src.Path, err)
            }
            sourceHashes[src.Mount] = h
        }

        key := registry.SpecHash(step, imageDigest, inputHashes, sourceHashes)
        tag := registry.Tag(p.Registry, stepName, key)
        specHashes[stepName] = key

        // Cache-Check: local-first, dann remote
        local, remote := registry.Find(tag)
        switch {
        case local:
            fmt.Printf("⏭  %s (lokal gecacht: %s)\n", stepName, tag)
            outputDirs[stepName] = cachedOutputDir(tag)
            continue
        case remote:
            fmt.Printf("⬇  %s (remote gecacht: %s)\n", stepName, tag)
            if err := registry.Pull(tag); err != nil {
                log.Fatalf("❌ %s: pull fehlgeschlagen: %v", stepName, err)
            }
            outputDirs[stepName] = cachedOutputDir(tag)
            continue
        }

        // Ausführen
        fmt.Printf("▶  %s\n", stepName)

        outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
        if err != nil {
            log.Fatal(err)
        }

        // Secrets auflösen
        secrets, err := resolveSecrets(step.Secrets, p.Secrets)
        if err != nil {
            log.Fatalf("❌ %s: secrets: %v", stepName, err)
        }

        // Input-Mounts aus vorherigen Output-Verzeichnissen
        inputMounts := []executor.Mount{}
        for _, inp := range step.Inputs {
            inputMounts = append(inputMounts, executor.Mount{
                Host:      filepath.Join(outputDirs[inp.From], inp.Name),
                Container: inp.Mount,
                ReadOnly:  true,
            })
        }

        // Source-Mounts
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
            log.Fatalf("❌ %s: ausführung fehlgeschlagen: %v", stepName, err)
        }

        outputDirs[stepName] = outDir

        // Outputs in Registry pushen
        if err := registry.PushArtifact(outDir, tag); err != nil {
            log.Fatalf("❌ %s: push fehlgeschlagen: %v", stepName, err)
        }
        fmt.Printf("✅ %s → %s\n", stepName, tag)
    }
}

// --- Hilfsfunktionen --------------------------------------------------------

func resolveDigest(imageRef string) (string, error) {
    // Image-Ref enthält bereits @sha256: — der Digest ist der Ref selbst
    // Für den Hash nutzen wir den Teil nach dem @
    for i, c := range imageRef {
        if c == '@' {
            return imageRef[i+1:], nil
        }
    }
    return "", fmt.Errorf("kein digest in image-ref %q — @sha256:... erforderlich", imageRef)
}

func cachedOutputDir(tag string) string {
    // Lokaler Output wird aus dem Container Store gemountet
    // (vereinfacht — in der Praxis: skopeo copy containers-storage → lokales Dir)
    return "/tmp/strike-cache/" + sanitize(tag)
}

func resolveSecrets(
    refs []pipeline.SecretRef,
    sources map[string]pipeline.SecretSource,
) (map[string]string, error) {
    result := map[string]string{}
    for _, ref := range refs {
        source, ok := sources[ref.Name]
        if !ok {
            return nil, fmt.Errorf("secret %q nicht in pipeline.secrets definiert", ref.Name)
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
            return "", fmt.Errorf("env-variable %q nicht gesetzt", source[6:])
        }
        return val, nil
    case len(source) > 7 && source[:7] == "file://":
        data, err := os.ReadFile(source[7:])
        return string(data), err
    default:
        return "", fmt.Errorf("unbekannte secret-quelle: %q (unterstützt: env://, file://)", source)
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
