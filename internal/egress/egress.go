// Package egress builds pasta command-line arguments for
// per-step container networking.
//
// Each step container is launched with --network=pasta:<args>,
// where <args> is the comma-joined output of BuildPastaArgs.
// The arguments restrict the container's network to only the
// resolver and mediator listeners: there is no other egress
// path because pasta is run in splice-only mode (no tap
// interface).
//
// Architectural decision: see docs/ROADMAP-ADR-028.md D24
// (egress filter mechanism: splice-only + selective port
// forwarding).
package egress

import (
	"fmt"
)

// SSHForward is one SSH peer's TCP port pair: the container-side port
// the step's SSH client connects to and the host-side port strike's
// per-peer raw-TCP forwarder listens on.
type SSHForward struct {
	ContainerPort uint16
	HostPort      uint16
}

// BuildPastaArgs returns the pasta options for a step container.
// The container sees the resolver on resolverPort (53), the mediator
// on mediatorPort (443), and each SSH peer on its container port;
// strike binds these listeners host-side on the unprivileged host
// ports (strike is rootless and cannot bind <1024). pasta's -T/-U
// forward spec remaps the container port to the host port with the
// "container:host" syntax and accepts no listening address (only
// -t/-u do), which is why per-step distinctness lives in the host
// port rather than a per-step address.
//
// Output order:
//
//	--splice-only
//	-T <resolverPort>:<resolverHostPort>
//	-T <mediatorPort>:<mediatorHostPort>
//	-U <resolverPort>:<resolverHostPort>
//	-T <sshContainerPort>:<sshHostPort>   (one per SSH peer, in order)
//
// The -U forward for the resolver port is essential: DNS clients try
// UDP first, falling back to TCP only on truncation. Without it,
// container DNS queries time out on UDP. SSH forwards are TCP-only.
//
// Byte-identical for byte-identical inputs.
func BuildPastaArgs(resolverPort, resolverHostPort, mediatorPort, mediatorHostPort uint16, ssh []SSHForward) []string {
	args := []string{
		"--splice-only",
		"-T", fmt.Sprintf("%d:%d", resolverPort, resolverHostPort),
		"-T", fmt.Sprintf("%d:%d", mediatorPort, mediatorHostPort),
		"-U", fmt.Sprintf("%d:%d", resolverPort, resolverHostPort),
	}
	for _, f := range ssh {
		args = append(args, "-T", fmt.Sprintf("%d:%d", f.ContainerPort, f.HostPort))
	}
	return args
}
