package capsule

import (
	"fmt"
	"net/netip"
)

// Loopback address-range constants. 127.0.0.40 .. 127.0.0.254 is
// chosen to avoid common loopback uses (127.0.0.1 host, 127.0.0.11
// docker-DNS, etc.) and leaves 215 addresses, comfortably above
// any realistic mediated-step count.
const (
	loopbackStart = 40
	loopbackMax   = 254
	loopbackCount = loopbackMax - loopbackStart + 1
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
	if len(stepNames) > loopbackCount {
		return nil, fmt.Errorf(
			"capsule: %d mediated steps exceeds max %d "+
				"(loopback range 127.0.0.%d-127.0.0.%d)",
			len(stepNames), loopbackCount, loopbackStart, loopbackMax)
	}
	out := make(map[string]netip.Addr, len(stepNames))
	for i, name := range stepNames {
		out[name] = netip.AddrFrom4([4]byte{127, 0, 0, uint8(loopbackStart + i)})
	}
	return out, nil
}
