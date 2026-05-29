package capsule

import (
	"fmt"
)

// Host-port allocation. Each container unit (run step, state capture,
// or deploy-method container) consumes a contiguous block of two host
// ports: the resolver and the mediator. Blocks are laid out in input
// order starting at hostPortBase. strike runs rootless and cannot bind
// <1024; base sits well above that. The container always sees
// 127.0.0.1:53 (DNS) and 127.0.0.1:443 (HTTPS); pasta -T/-U forward
// those to the unit's host ports. Per-unit distinctness lives in the
// host port because pasta -T/-U accept no listening address (only -t/-u
// do); the loopback address is shared across units and never collides,
// since each unit has its own netns. SSH egress needs no per-peer host
// port: the step reaches the front on port 22 (ADR-038 D5) and the
// capsule dials the peer directly.
const (
	hostPortBase uint16 = 5353
	// hostPortBudget is the number of host ports available above
	// hostPortBase. The sum of all per-unit block sizes must not
	// exceed it.
	hostPortBudget = 65535 - int(hostPortBase)
)

// StepPortReq is one container unit's port requirement: a unique name.
// Every unit gets the same two-port block (resolver + mediator); the
// name keys the result map.
type StepPortReq struct {
	Name string
}

// HostPorts is one unit's set of host-side bind ports: the resolver and
// the mediator.
type HostPorts struct {
	Resolver uint16
	Mediator uint16
}

// AllocatePorts maps each unit name to a distinct HostPorts block,
// assigned contiguously in input order: a two-port block (resolver +
// mediator) per unit. The function is pure: the same input always
// produces the same output map, on every run and machine.
//
// Called once per lane run from cmdRun, after the container units
// (run steps, captures, deploy-method containers) have been
// enumerated in lane-file order. The result is stored on runContext
// and read when each unit executes.
//
// Returns an error if the total host-port demand exceeds the budget.
// Duplicate names collapse to one map entry; callers pass distinct
// unit names.
func AllocatePorts(reqs []StepPortReq) (map[string]HostPorts, error) {
	total := 2 * len(reqs)
	if total > hostPortBudget {
		return nil, fmt.Errorf(
			"capsule: host-port demand %d exceeds budget %d",
			total, hostPortBudget)
	}
	out := make(map[string]HostPorts, len(reqs))
	next := int(hostPortBase)
	for _, r := range reqs {
		out[r.Name] = HostPorts{
			Resolver: uint16(next),
			Mediator: uint16(next + 1),
		}
		next += 2
	}
	return out, nil
}
