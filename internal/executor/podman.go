package executor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/istr/strike/internal/capsule"
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
	// ImageRef overrides Step.Image when non-empty. Set by the caller
	// for image_from steps so that Step.Image remains the parsed YAML
	// value and the executor sees the producer's content-addressed
	// digest reference (localhost/strike/<lane>/<step>@sha256:<D>).
	// When empty, Step.Image is used unchanged. ADR-045: the base is
	// always a digest-pinned reference.
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

	// The container has no bind mounts: inputs are seeded into the workdir
	// volume before start (r.Seeds), trust material rides named volumes, and
	// SSH egress reaches the front on port 22 -- no agent socket (ADR-038 D6).
	opts := container.DefaultSecureOpts()
	if r.Step.Image != nil {
		opts.Image = string(*r.Step.Image)
	}
	if r.ImageRef != "" {
		opts.Image = r.ImageRef
	}
	// ADR-045: a step executes only a digest-pinned image. External bases
	// are digest-pinned at the schema boundary (ADR-011); image_from bases
	// arrive as a content-addressed local reference. Reject anything else
	// structurally, so an execute-by-tag path cannot reappear.
	if !strings.Contains(opts.Image, "@sha256:") {
		return "", fmt.Errorf("executor: refusing to run non-digest-pinned image %q (ADR-045)", opts.Image)
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
