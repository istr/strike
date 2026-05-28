package executor

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

// Run holds the configuration for executing a step container.
type Run struct {
	Engine  container.Engine
	Capsule *capsule.NetworkCapsule // non-nil for HTTPS-mediated steps
	Secrets map[string]lane.SecretString
	Step    *lane.Step
	// VolumeName is the engine-managed writable workdir volume. Empty for a
	// step with no workdir (no writable surface, no outputs). The caller
	// owns the volume lifecycle (create before, remove after extraction).
	VolumeName string
	// ImageRef overrides Step.Image when non-empty. Set by the
	// caller for image_from steps so that Step.Image remains the
	// parsed YAML value and the executor sees the producer's
	// local WrapTag. When empty, Step.Image is used unchanged.
	ImageRef  string
	CAVolume  string // lane-wide CA volume name; mounted r/o at /etc/ssl/certs; required when Capsule != nil
	SSHVolume string // per-step SSH trust volume name; mounted r/o at /etc/ssh; empty when step has no SSH peers
	// Seeds carry input content into the workdir volume before start
	// (ADR-036 inside-workdir delivery). Built by the caller; the executor
	// passes them through to ContainerRunHeld unchanged.
	Seeds []container.Seed
	// ImageVolumes carry inputs mounted outside the workdir as read-only
	// engine-native image mounts (ADR-036 outside-workdir delivery). Built by
	// the caller; the executor copies them into RunOpts unchanged.
	ImageVolumes []container.ImageVolume
}

// Execute runs the step container held (not auto-removed) and returns the
// container id so the caller can extract outputs via the engine archive API
// and then purge it. The id is returned even on error when the container was
// created, so the caller can always clean up.
func (r Run) Execute(ctx context.Context) (string, error) {
	scratchDir, err := os.MkdirTemp("", "strike-ssh-")
	if err != nil {
		return "", fmt.Errorf("ssh scratch: %w", err)
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

	// Inputs are delivered by seeding the workdir volume before start
	// (r.Seeds), not by bind mounts. Only agent socket mounts remain.
	var mounts []container.Mount
	mounts, err = appendSSHMounts(ctx, r.Step.Peers, scratchDir, mounts, env)
	if err != nil {
		return "", err
	}

	opts := container.DefaultSecureOpts()
	if r.Step.Image != nil {
		opts.Image = string(*r.Step.Image)
	}
	if r.ImageRef != "" {
		opts.Image = r.ImageRef
	}
	opts.Cmd = r.Step.Args
	opts.Env = env

	if r.Capsule == nil {
		return "", fmt.Errorf("executor: container step requires a capsule")
	}
	if r.CAVolume == "" {
		return "", fmt.Errorf("executor: Capsule set without CAVolume")
	}
	// Mask /etc/ssl/certs with the lane-wide CA volume (read-only). The
	// volume holds only ca-certificates.crt (the ephemeral CA); the base
	// image's system CA bundle and hashed symlinks are masked. cert.pem
	// and /etc/pki bundle paths are symlinks into /etc/ssl/certs and
	// resolve through it. See ADR-028 D18.
	opts.TrustVolumes = append(opts.TrustVolumes, container.VolumeMount{
		Name: r.CAVolume,
		Dest: "/etc/ssl/certs",
	})
	if r.SSHVolume != "" {
		opts.TrustVolumes = append(opts.TrustVolumes, container.VolumeMount{
			Name: r.SSHVolume,
			Dest: "/etc/ssh",
		})
	}
	opts.Network = "pasta"
	opts.PastaArgs = r.Capsule.PastaArgs()
	opts.DNSServers = []string{r.Capsule.ResolverAddr().Addr().String()}

	opts.Mounts = mounts
	opts.ImageVolumes = r.ImageVolumes
	if r.Step.Workdir != nil {
		opts.Workdir = r.Step.Workdir.String()
		if r.VolumeName != "" {
			opts.Volume = &container.VolumeMount{
				Name: r.VolumeName,
				Dest: r.Step.Workdir.String(),
			}
		}
	}
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr

	id, exitCode, err := r.Engine.ContainerRunHeld(ctx, opts, r.Seeds)
	if err != nil {
		return id, fmt.Errorf("container execution: %w", err)
	}
	if exitCode != 0 {
		return id, fmt.Errorf("container exited with code %d", exitCode)
	}
	return id, nil
}

// appendSSHMounts handles the SSH agent socket bind-mount and its env
// var. The SSH trust material (known_hosts, ssh_config) now rides a
// per-step trust volume mounted at /etc/ssh by the orchestrator (see
// cmd/strike/run.go planTrustVolumes); the agent socket is a live Unix
// socket and cannot ride a volume, so it stays a bind-mount until the
// ADR-038 front removes it entirely (roadmap item 6).
func appendSSHMounts(ctx context.Context, peers []lane.Peer, scratchDir string, mounts []container.Mount, env map[string]string) ([]container.Mount, error) {
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

// SSHContainerPorts maps each SSH peer host (no port) to the
// container-side loopback port the step's SSH client must use,
// assigned capsule.SSHContainerPortBase + k in peer-list order. The
// mapping is consumed by ConfigureSSHPeers (ssh_config Port directives)
// and is consistent by construction with the capsule's SSH forwards,
// which use the same base and order. Returns nil when no SSH peers are
// present.
func SSHContainerPorts(peers []lane.Peer) map[string]uint16 {
	var out map[string]uint16
	k := 0
	for _, p := range peers {
		sp, ok := p.(lane.SSHPeer)
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]uint16{}
		}
		host, _ := capsule.SplitSSHHostPort(string(sp.Host))
		out[host] = capsule.SSHContainerPortBase + uint16(k)
		k++
	}
	return out
}
