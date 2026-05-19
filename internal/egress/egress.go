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

// BuildPastaArgs returns the pasta command-line options for a
// step container whose DNS resolver listens at resolverAddr and
// whose TLS mediator listens at mediatorAddr (both in the
// strike controller's init namespace, on loopback).
//
// The returned slice is in the exact order pasta expects:
//
//	--splice-only
//	-T <resolverIP>/<resolverPort>
//	-T <mediatorIP>/<mediatorPort>
//
// The slice is byte-identical for byte-identical inputs.
//
// Panics if either address is IPv6. IPv6 egress is out of
// scope for this PR (see D24's "address family" note in the
// roadmap).
func BuildPastaArgs(resolverAddr, mediatorAddr netip.AddrPort) []string {
	if !resolverAddr.Addr().Is4() {
		panic(fmt.Sprintf("egress: resolverAddr must be IPv4, got %s", resolverAddr))
	}
	if !mediatorAddr.Addr().Is4() {
		panic(fmt.Sprintf("egress: mediatorAddr must be IPv4, got %s", mediatorAddr))
	}
	return []string{
		"--splice-only",
		"-T", fmt.Sprintf("%s/%d", resolverAddr.Addr(), resolverAddr.Port()),
		"-T", fmt.Sprintf("%s/%d", mediatorAddr.Addr(), mediatorAddr.Port()),
	}
}
