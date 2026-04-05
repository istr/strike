package executor

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

// Run holds the configuration for executing a step container.
type Run struct {
	Engine       container.Engine
	Secrets      map[string]lane.SecretString
	Step         *lane.Step
	OutputDir    string
	InputMounts  []Mount
	SourceMounts []Mount
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
		// Log secret key with redacted value for audit trail.
		// SecretString.String() returns "[REDACTED]", preventing leakage.
		log.Printf("SECRET %s=%s", k, v)
		env[k] = v.Expose()
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

	opts := container.DefaultSecureOpts()
	opts.Image = r.Step.Image
	opts.Cmd = r.Step.Args
	opts.Env = env
	opts.Mounts = mounts
	opts.Network = NetworkMode(r.Step.Network)
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr

	exitCode, err := r.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return fmt.Errorf("container execution: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("container exited with code %d", exitCode)
	}
	return nil
}

// NetworkMode returns the container network mode string for the given setting.
func NetworkMode(enabled bool) string {
	if enabled {
		return "" // default bridge
	}
	return "none"
}
