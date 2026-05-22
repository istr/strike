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

// BuildPastaArgs returns the pasta options for a step container.
// The container sees the resolver on resolverPort (53) and the
// mediator on mediatorPort (443); strike binds these listeners
// host-side on the unprivileged resolverHostPort and mediatorHostPort
// (strike is rootless and cannot bind <1024). pasta's -T/-U forward
// spec remaps the container port to the host port with the
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
//
// The -U forward for the resolver port is essential: DNS clients try
// UDP first, falling back to TCP only on truncation. Without it,
// container DNS queries time out on UDP.
//
// Byte-identical for byte-identical inputs.
func BuildPastaArgs(resolverPort, resolverHostPort, mediatorPort, mediatorHostPort uint16) []string {
	return []string{
		"--splice-only",
		"-T", fmt.Sprintf("%d:%d", resolverPort, resolverHostPort),
		"-T", fmt.Sprintf("%d:%d", mediatorPort, mediatorHostPort),
		"-U", fmt.Sprintf("%d:%d", resolverPort, resolverHostPort),
	}
}
