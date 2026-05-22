package capsule

import (
	"fmt"
)

// Host-port allocation. Each mediated step consumes two contiguous
// unprivileged host ports: the resolver at base+2i and the mediator at
// base+2i+1, assigned in lane-file order. strike runs rootless and
// cannot bind <1024; base sits well above that. The container always
// sees 127.0.0.1:53 (DNS) and 127.0.0.1:443 (HTTPS); pasta -T/-U
// forward those to the step's host ports. Per-step distinctness lives
// in the host port because pasta -T/-U accept no listening address
// (only -t/-u do); the loopback address is shared across steps and
// never collides, since each step has its own netns.
const (
	hostPortBase uint16 = 5353
	// hostPortCap is the maximum mediated-step count: two ports per
	// step, staying within the uint16 range above hostPortBase.
	hostPortCap = (65535 - int(hostPortBase)) / 2
)

// HostPorts is the per-step pair of host-side bind ports.
type HostPorts struct {
	Resolver uint16
	Mediator uint16
}

// AllocatePorts maps each step name to a distinct HostPorts pair,
// assigned base+2i / base+2i+1 in input order. The function is pure:
// the same input slice always produces the same output map, on every
// run and machine.
//
// Called once per lane run from cmdRun, after dispatch classification
// has identified the mediated step names (in lane-file order). The
// result is stored on runContext and read when each step executes.
//
// Returns an error if len(stepNames) exceeds the available range.
// Duplicate names collapse to one map entry; callers pass distinct
// step names (lane step names are unique by schema).
func AllocatePorts(stepNames []string) (map[string]HostPorts, error) {
	if len(stepNames) > hostPortCap {
		return nil, fmt.Errorf(
			"capsule: %d mediated steps exceeds host-port capacity %d",
			len(stepNames), hostPortCap)
	}
	out := make(map[string]HostPorts, len(stepNames))
	for i, name := range stepNames {
		n := uint16(i)
		out[name] = HostPorts{
			Resolver: hostPortBase + 2*n,
			Mediator: hostPortBase + 2*n + 1,
		}
	}
	return out, nil
}
