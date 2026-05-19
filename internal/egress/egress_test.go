package egress_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/istr/strike/internal/egress"
)

func TestBuildPastaArgs_HappyPath(t *testing.T) {
	resolver := netip.MustParseAddrPort("127.0.0.40:53")
	mediator := netip.MustParseAddrPort("127.0.0.41:443")
	got := egress.BuildPastaArgs(resolver, mediator)
	want := []string{
		"--splice-only",
		"-T", "127.0.0.40/53",
		"-T", "127.0.0.41/443",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}

func TestBuildPastaArgs_DistinctPerStepAddresses(t *testing.T) {
	// Two parallel steps with distinct loopback allocations
	// produce distinct argument lists. Verifies that the
	// function's output discriminates step-to-step.
	step1Resolver := netip.MustParseAddrPort("127.0.0.40:53")
	step1Mediator := netip.MustParseAddrPort("127.0.0.41:443")
	step2Resolver := netip.MustParseAddrPort("127.0.0.42:53")
	step2Mediator := netip.MustParseAddrPort("127.0.0.43:443")
	args1 := egress.BuildPastaArgs(step1Resolver, step1Mediator)
	args2 := egress.BuildPastaArgs(step2Resolver, step2Mediator)
	if reflect.DeepEqual(args1, args2) {
		t.Error("expected distinct argument lists for distinct address pairs, got identical")
	}
}

func TestBuildPastaArgs_Deterministic(t *testing.T) {
	// Same inputs produce byte-identical outputs across calls.
	resolver := netip.MustParseAddrPort("127.0.0.40:53")
	mediator := netip.MustParseAddrPort("127.0.0.41:443")
	a := egress.BuildPastaArgs(resolver, mediator)
	b := egress.BuildPastaArgs(resolver, mediator)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("non-deterministic output: %#v vs %#v", a, b)
	}
}

func TestBuildPastaArgs_HighPort(t *testing.T) {
	// The port formatter must handle the full uint16 range.
	resolver := netip.MustParseAddrPort("127.0.0.40:65535")
	mediator := netip.MustParseAddrPort("127.0.0.41:8443")
	got := egress.BuildPastaArgs(resolver, mediator)
	want := []string{
		"--splice-only",
		"-T", "127.0.0.40/65535",
		"-T", "127.0.0.41/8443",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}

func TestBuildPastaArgs_PanicsOnIPv6Resolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on IPv6 resolver address, got none")
		}
	}()
	resolver := netip.MustParseAddrPort("[::1]:53")
	mediator := netip.MustParseAddrPort("127.0.0.41:443")
	_ = egress.BuildPastaArgs(resolver, mediator)
}

func TestBuildPastaArgs_PanicsOnIPv6Mediator(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on IPv6 mediator address, got none")
		}
	}()
	resolver := netip.MustParseAddrPort("127.0.0.40:53")
	mediator := netip.MustParseAddrPort("[::1]:443")
	_ = egress.BuildPastaArgs(resolver, mediator)
}

func TestBuildPastaArgs_StructuralInvariants(t *testing.T) {
	// The argument list always starts with --splice-only and
	// contains exactly two -T entries. This pins the structural
	// shape independently of the address values, in case future
	// refactoring changes the address formatting.
	resolver := netip.MustParseAddrPort("127.0.0.40:53")
	mediator := netip.MustParseAddrPort("127.0.0.41:443")
	args := egress.BuildPastaArgs(resolver, mediator)
	if len(args) != 5 {
		t.Fatalf("expected exactly 5 arguments, got %d: %#v", len(args), args)
	}
	if args[0] != "--splice-only" {
		t.Errorf("args[0] = %q, want %q", args[0], "--splice-only")
	}
	tCount := 0
	for i, a := range args {
		if a == "-T" {
			tCount++
			if i+1 >= len(args) {
				t.Errorf("dangling -T at end of args")
			}
		}
	}
	if tCount != 2 {
		t.Errorf("expected exactly 2 -T entries, got %d", tCount)
	}
}
