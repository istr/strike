package executor

import (
    "fmt"
    "os"
    "os/exec"

    "github.com/istr/strike/lane"
)

type Run struct {
    Step        *lane.Step
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
    args := []string{
        "run", "--rm",
        "--userns=keep-id",
        "--env", "XDG_RUNTIME_DIR=/tmp/run",
        "--env", "XDG_DATA_HOME=/tmp/data",
    }

    if !r.Step.Network {
        args = append(args, "--network=none")
    }

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

    // Non-sensitive environment variables (inline values)
    for k, v := range r.Step.Env {
        args = append(args, "--env", k+"="+v)
    }

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

