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
	Engine    container.Engine
	Capsule   *capsule.NetworkCapsule // non-nil for HTTPS-mediated steps
	Secrets   map[string]lane.SecretString
	Step      *lane.Step
	OutputDir string
	// ImageRef overrides Step.Image when non-empty. Set by the
	// caller for image_from steps so that Step.Image remains the
	// parsed YAML value and the executor sees the producer's
	// local WrapTag. When empty, Step.Image is used unchanged.
	ImageRef     string
	CABundlePath string // host path of the lane-wide CA PEM; required when Capsule != nil
	InputMounts  []Mount
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

	sshContainerPorts := SSHContainerPorts(r.Step.Peers)
	mounts, err = appendSSHMounts(ctx, r.Step.Peers, scratchDir, sshContainerPorts, mounts, env)
	if err != nil {
		return err
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
		return fmt.Errorf("executor: container step requires a capsule")
	}
	if r.CABundlePath == "" {
		return fmt.Errorf("executor: Capsule set without CABundlePath")
	}
	// Bind-mount the ephemeral CA over the three common system
	// CA-bundle paths. The base image will have one or two of
	// these; Podman creates the target file if missing. See D18.
	for _, target := range caBundleTargets {
		mounts = append(mounts, container.Mount{
			Source:   r.CABundlePath,
			Target:   target,
			ReadOnly: true,
		})
	}
	opts.Network = "pasta"
	opts.PastaArgs = r.Capsule.PastaArgs()
	opts.DNSServers = []string{r.Capsule.ResolverAddr().Addr().String()}

	opts.Mounts = mounts
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

// caBundleTargets is the set of system CA-bundle paths strike
// bind-mounts when a step uses pasta-mediation. The ephemeral CA
// is mounted to all three; the base image populates one or two.
// See docs/ROADMAP-ADR-028.md D18 (system CA bundle replacement).
var caBundleTargets = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Alpine
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora/RHEL/CentOS
	"/etc/ssl/cert.pem",                                 // Alpine (alt path)
}

// CABundleTargets returns the system CA-bundle paths strike bind-mounts
// the ephemeral CA over for capsule-mediated containers. Exposed for
// the deploy package, which mediates its own container paths.
func CABundleTargets() []string {
	out := make([]string, len(caBundleTargets))
	copy(out, caBundleTargets)
	return out
}

// appendSSHMounts configures SSH peer known_hosts, the strike ssh_config
// (per-peer Port directives), and the agent proxy, appending any
// resulting mounts and injecting env vars. containerPorts maps each SSH
// peer host (no port) to its container-side port.
func appendSSHMounts(ctx context.Context, peers []lane.Peer, scratchDir string, containerPorts map[string]uint16, mounts []container.Mount, env map[string]string) ([]container.Mount, error) {
	sshMounts, sshEnv, err := ConfigureSSHPeers(peers, scratchDir, containerPorts)
	if err != nil {
		return nil, fmt.Errorf("ssh peer setup: %w", err)
	}
	mounts = append(mounts, sshMounts...)
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
