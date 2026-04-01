package executor

import (
	"context"
	"fmt"
	"os"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

// Run holds the configuration for executing a step container.
type Run struct {
	Engine       container.Engine
	Step         *lane.Step
	InputMounts  []Mount
	SourceMounts []Mount
	OutputDir    string
	Secrets      map[string]string // env-name -> plaintext
}

// Mount describes a bind mount from host to container.
type Mount struct {
	Host      string
	Container string
	ReadOnly  bool
}

// Execute runs the step container via the container engine API.
// Secrets are passed as env vars in the API request body (JSON over Unix
// socket), never via os.Setenv or process arguments.
func (r Run) Execute(ctx context.Context) error {
	// Build environment (non-sensitive + secrets)
	env := make(map[string]string, len(r.Step.Env)+len(r.Secrets)+2)
	for k, v := range r.Step.Env {
		env[k] = v
	}
	for k, v := range r.Secrets {
		env[k] = v
	}
	env["XDG_RUNTIME_DIR"] = "/tmp/run"
	env["XDG_DATA_HOME"] = "/tmp/data"

	// Build mounts
	var mounts []container.Mount
	for _, m := range r.InputMounts {
		mounts = append(mounts, container.Mount{
			Source: m.Host, Target: m.Container, ReadOnly: m.ReadOnly,
		})
	}
	for _, m := range r.SourceMounts {
		mounts = append(mounts, container.Mount{
			Source: m.Host, Target: m.Container, ReadOnly: true,
		})
	}
	// Output directory
	mounts = append(mounts, container.Mount{
		Source:  r.OutputDir,
		Target:  "/out",
		Options: []string{"noexec", "nosuid"},
	})

	exitCode, err := r.Engine.ContainerRun(ctx, container.RunOpts{
		Image:       r.Step.Image,
		Cmd:         r.Step.Args,
		Env:         env,
		Mounts:      mounts,
		Network:     networkMode(r.Step.Network),
		CapDrop:     []string{"ALL"},
		ReadOnly:    true,
		SecurityOpt: []string{"no-new-privileges"},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=512m"},
		UsernsMode:  "keep-id",
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Remove:      true,
	})
	if err != nil {
		return fmt.Errorf("container execution: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("container exited with code %d", exitCode)
	}
	return nil
}

func networkMode(enabled bool) string {
	if enabled {
		return "" // default bridge
	}
	return "none"
}
