package executor

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

// Run holds the configuration for executing a step container.
type Run struct {
	Engine    container.Engine
	Secrets   map[string]lane.SecretString
	Step      *lane.Step
	OutputDir string
	// ImageRef overrides Step.Image when non-empty. Set by the
	// caller for image_from steps so that Step.Image remains the
	// parsed YAML value and the executor sees the producer's
	// local WrapTag. When empty, Step.Image is used unchanged.
	ImageRef    string
	InputMounts []Mount
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
	scratchDir, err := os.MkdirTemp("", "strike-ssh-")
	if err != nil {
		return fmt.Errorf("ssh scratch: %w", err)
	}
	defer closer.Remove(scratchDir, "executor scratch")

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
	// Output directory
	mounts = append(mounts, container.Mount{
		Source:  r.OutputDir,
		Target:  "/out",
		Options: []string{"noexec", "nosuid"},
	})

	mounts, err = appendSSHMounts(ctx, r.Step.Peers, scratchDir, mounts, env)
	if err != nil {
		return err
	}

	opts := container.DefaultSecureOpts()
	if r.Step.Image != nil {
		opts.Image = *r.Step.Image
	}
	if r.ImageRef != "" {
		opts.Image = r.ImageRef
	}
	opts.Cmd = r.Step.Args
	opts.Env = env
	opts.Mounts = mounts
	opts.Network = NetworkMode(r.Step.Peers)
	if r.Step.Workdir != nil {
		opts.Workdir = r.Step.Workdir.String()
	}
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

// appendSSHMounts configures SSH peer known_hosts and agent proxy,
// appending any resulting mounts and injecting env vars.
func appendSSHMounts(ctx context.Context, peers []lane.Peer, scratchDir string, mounts []container.Mount, env map[string]string) ([]container.Mount, error) {
	sshMount, sshEnv, err := ConfigureSSHPeers(peers, scratchDir)
	if err != nil {
		return nil, fmt.Errorf("ssh peer setup: %w", err)
	}
	if sshMount != nil {
		mounts = append(mounts, *sshMount)
	}
	for k, v := range sshEnv {
		env[k] = v
	}

	agentMount, agentEnv, err := StartAgentProxy(ctx, peers, scratchDir)
	if err != nil {
		return nil, fmt.Errorf("ssh agent proxy setup: %w", err)
	}
	if agentMount != nil {
		mounts = append(mounts, *agentMount)
	}
	for k, v := range agentEnv {
		env[k] = v
	}
	return mounts, nil
}

// NetworkMode returns the container engine network mode string for the
// given peer list. An empty list means --network=none; a non-empty list
// means --network=bridge. Phase 1 enforcement is declaratory: the peer
// list itself flows into the deploy attestation; the kernel sees only
// the bridge/none switch.
func NetworkMode(peers []lane.Peer) string {
	if len(peers) == 0 {
		return "none"
	}
	return "bridge"
}
