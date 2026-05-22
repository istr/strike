package capsule

import (
	"fmt"
	"net/netip"
)

// Synthetic loopback range. The whole 127.0.0.0/8 is loopback on
// Linux; 127.64.0.0/16 sits clear of the collision-prone bottom
// (127.0.0.0/24 carries 127.0.0.1 localhost, 127.0.0.53
// systemd-resolved, 127.0.0.11 docker DNS) and clear of the "127.1"
// shorthand. The second octet 64 is arbitrary-but-fixed. The /16
// gives 65535 usable addresses (index 0 maps to 127.64.0.1). The
// address is a routing identifier only and carries no semantics.
const (
	loopbackOctet2 = 64
	loopbackCap    = 1<<16 - 1
)

// AllocateAddresses maps each step name to a distinct IPv4
// loopback address, assigned 127.0.0.40, 127.0.0.41, ... in input
// order. The function is pure: the same input slice always
// produces the same output map, on every run and machine.
//
// Called once per lane run from cmdRun, after dispatch
// classification has identified the mediated step names (in
// lane-file order). The result is stored on runContext and read
// when each step executes.
//
// Returns an error if len(stepNames) exceeds the available range.
// Duplicate names in the input collapse to one map entry; callers
// pass distinct step names (lane step names are unique by schema).
func AllocateAddresses(stepNames []string) (map[string]netip.Addr, error) {
	if len(stepNames) > loopbackCap {
		return nil, fmt.Errorf(
			"capsule: %d mediated steps exceeds 127.64.0.0/16 capacity %d",
			len(stepNames), loopbackCap)
	}
	out := make(map[string]netip.Addr, len(stepNames))
	for i, name := range stepNames {
		n := uint16(i + 1) // index 0 -> 127.64.0.1, avoiding the .0.0 base
		out[name] = netip.AddrFrom4([4]byte{127, loopbackOctet2, byte(n >> 8), byte(n)})
	}
	return out, nil
}
