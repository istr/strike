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
	"net/netip"
)

// BuildPastaArgs returns the pasta options for a step container
// whose resolver listens at stepAddr:resolverPort (UDP+TCP) and
// whose mediator listens at stepAddr:mediatorPort (TCP). Both bind
// the same loopback address; ports disambiguate.
//
// Output order:
//
//	--splice-only
//	-T <stepAddr>/<resolverPort>
//	-T <stepAddr>/<mediatorPort>
//	-U <stepAddr>/<resolverPort>
//
// The -U forward for the resolver port is essential: DNS clients
// try UDP first, falling back to TCP only on truncation. Without
// it, container DNS queries time out on UDP.
//
// Byte-identical for byte-identical inputs. Panics if stepAddr is
// IPv6 (out of scope; see ROADMAP-ADR-028.md D24).
func BuildPastaArgs(stepAddr netip.Addr, resolverPort, mediatorPort uint16) []string {
	if !stepAddr.Is4() {
		panic(fmt.Sprintf("egress: stepAddr must be IPv4, got %s", stepAddr))
	}
	addr := stepAddr.String()
	return []string{
		"--splice-only",
		"-T", fmt.Sprintf("%s/%d", addr, resolverPort),
		"-T", fmt.Sprintf("%s/%d", addr, mediatorPort),
		"-U", fmt.Sprintf("%s/%d", addr, resolverPort),
	}
}
