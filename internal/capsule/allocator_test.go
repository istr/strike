package capsule_test

import (
	"reflect"
	"testing"

	"github.com/istr/strike/internal/capsule"
)

func TestAllocatePorts_Empty(t *testing.T) {
	ports, err := capsule.AllocatePorts(nil)
	if err != nil {
		t.Fatalf("AllocatePorts(nil): %v", err)
	}
	if len(ports) != 0 {
		t.Errorf("expected empty map, got %d entries", len(ports))
	}
}

func TestAllocatePorts_Contiguous(t *testing.T) {
	ports, err := capsule.AllocatePorts([]capsule.StepPortReq{
		{Name: "a"}, {Name: "b"}, {Name: "c"},
	})
	if err != nil {
		t.Fatalf("AllocatePorts: %v", err)
	}
	want := map[string]capsule.HostPorts{
		"a": {Resolver: 5353, Mediator: 5354},
		"b": {Resolver: 5355, Mediator: 5356},
		"c": {Resolver: 5357, Mediator: 5358},
	}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("AllocatePorts = %#v, want %#v", ports, want)
	}
}

func TestAllocatePorts_Deterministic(t *testing.T) {
	in := []capsule.StepPortReq{{Name: "x"}, {Name: "y"}, {Name: "z"}}
	a, err := capsule.AllocatePorts(in)
	if err != nil {
		t.Fatalf("AllocatePorts: %v", err)
	}
	b, err := capsule.AllocatePorts(in)
	if err != nil {
		t.Fatalf("AllocatePorts: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("non-deterministic: %#v vs %#v", a, b)
	}
}

func TestAllocatePorts_SSHBlocks(t *testing.T) {
	ports, err := capsule.AllocatePorts([]capsule.StepPortReq{
		{Name: "a", SSHCount: 0},
		{Name: "b", SSHCount: 2},
		{Name: "c", SSHCount: 1},
	})
	if err != nil {
		t.Fatalf("AllocatePorts: %v", err)
	}
	want := map[string]capsule.HostPorts{
		"a": {Resolver: 5353, Mediator: 5354},
		"b": {Resolver: 5355, Mediator: 5356, SSH: []uint16{5357, 5358}},
		"c": {Resolver: 5359, Mediator: 5360, SSH: []uint16{5361}},
	}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("AllocatePorts = %#v, want %#v", ports, want)
	}
}
