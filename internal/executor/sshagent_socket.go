package executor

import "os"

// chmodAgentSocket sets the listening socket world-readable/writable
// so the step container (different UID under rootless Podman) can
// connect. Host-side exposure is bounded by the parent scratch
// directory (0o700). See ADR-025.
func chmodAgentSocket(path string) error {
	return os.Chmod(path, 0o666) //nolint:gosec // G302: ADR-025 SSH agent socket; scratchDir 0o700 bounds host-side access
}
