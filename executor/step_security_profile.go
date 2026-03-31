// Step container security profile.
//
// These are the podman run flags that strike uses for INNER step
// containers — the containers that execute individual build/deploy
// steps. This is NOT the outer executor container.
//
// Design principle: step containers are disposable, untrusted,
// maximally restricted execution environments. They receive
// typed inputs via read-only mounts and deliver typed outputs
// via a single writable mount point that strike controls.

package executor

// StepContainerFlags returns the podman run arguments for a step.
// These are constants — not configurable by the lane definition.
//
// The step definition controls only:
//   - which image to use (always digest-pinned)
//   - which inputs to mount (always read-only)
//   - which env vars to set
//   - whether network is enabled (default: no)
//   - the command (exec form, no shell)
//
// Everything else is locked down by strike.

// Base flags — always applied, unconditionally.
var baseFlags = []string{
	// Drop ALL capabilities. Steps don't need any.
	"--cap-drop=ALL",

	// Read-only root filesystem. The image is immutable.
	"--read-only",

	// Scratch space for the process. Cannot execute from here,
	// cannot create setuid files.
	"--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",

	// Remove container after exit. No state survives.
	"--rm",

	// No new privileges via setuid/setgid binaries.
	"--security-opt=no-new-privileges",
}

// Output mount — the single writable path for artifact delivery.
// Strike mounts a host directory here BEFORE the step runs, and
// extracts declared outputs AFTER the step exits.
//
// noexec: step cannot execute its own outputs
// nosuid: no setuid tricks
// The mount is writable because the step needs to write its outputs.
//
// Path is a constant: /out
// The step's OutputSpec.Path must be under /out.
func outputMount(hostDir string) []string {
	return []string{
		"-v", hostDir + ":/out:rw,noexec,nosuid",
	}
}

// Input mounts — read-only, one per declared input.
// The step cannot modify its inputs.
func inputMount(hostDir, containerPath string) []string {
	return []string{
		"-v", hostDir + ":" + containerPath + ":ro",
	}
}

// Network — disabled by default. Enabled only when the step
// definition explicitly sets network: true.
func networkFlag(enabled bool) []string {
	if enabled {
		return nil // use default (bridge) network
	}
	return []string{"--network=none"}
}

// Assembled command:
//
//   podman run \
//     --cap-drop=ALL \
//     --read-only \
//     --tmpfs /tmp:rw,noexec,nosuid,size=512m \
//     --rm \
//     --security-opt=no-new-privileges \
//     --network=none \                          # unless network: true
//     -v /strike/tmp/abc123/out:/out:rw,noexec,nosuid \
//     -v /strike/tmp/abc123/src:/src:ro \        # per input
//     -e CGO_ENABLED=0 \                         # per env
//     cgr.dev/chainguard/go@sha256:... \
//     build -trimpath -o /out/strike .            # exec form
//
// What the step container CANNOT do:
//   - Start nested containers (no podman, no /dev/fuse, no capabilities)
//   - Modify its own image (read-only root)
//   - Execute anything from /out or /tmp (noexec)
//   - Create setuid binaries anywhere (nosuid + no-new-privileges)
//   - Access the network (unless explicitly granted)
//   - Write anywhere except /out and /tmp
//   - Survive past its own exit (--rm)
//   - Escalate privileges in any way (cap-drop=ALL + no-new-privileges)
//
// What the step container CAN do:
//   - Read its inputs (mounted read-only)
//   - Execute its image's binaries (the image is the toolchain)
//   - Write outputs to /out (strike extracts and validates after)
//   - Write to /tmp for scratch (lost after exit)
//   - Access env vars (secrets injected by strike)
//   - Access the network (only if step declares network: true)
