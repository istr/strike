package executor

import (
    "fmt"
    "os"
    "os/exec"

    "github.com/istr/strike/pipeline"
)

type Run struct {
    Step        *pipeline.Step
    InputMounts []Mount
    SourceMounts []Mount
    OutputDir   string
    Secrets     map[string]string // env-name → plaintext
}

type Mount struct {
    Host      string
    Container string
    ReadOnly  bool
}

func (r Run) Execute() error {
    args := []string{"run", "--rm", "--network=none"}

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

    // Output-Verzeichnis
    args = append(args, "-v", r.OutputDir+":/out")

    // Secrets nur als Env-Namen übergeben — Werte über Prozess-Umgebung
    // werden nie in die args-Liste geschrieben (kein `ps aux`-Leak)
    for envName, val := range r.Secrets {
        args = append(args, "--env", envName)
        os.Setenv(envName, val)
    }

    args = append(args, string(r.Step.Image))
    args = append(args, r.Step.Args...)

    cmd := exec.Command("podman", args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}
