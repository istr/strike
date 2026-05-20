package egress_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/istr/strike/internal/egress"
)

func TestBuildPastaArgs_HappyPath(t *testing.T) {
	addr := netip.MustParseAddr("127.0.0.40")
	got := egress.BuildPastaArgs(addr, 53, 443)
	want := []string{
		"--splice-only",
		"-T", "127.0.0.40/53",
		"-T", "127.0.0.40/443",
		"-U", "127.0.0.40/53",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}

func TestBuildPastaArgs_DistinctPerStepAddresses(t *testing.T) {
	// Two parallel steps with distinct loopback allocations
	// produce distinct argument lists. Verifies that the
	// function's output discriminates step-to-step.
	args1 := egress.BuildPastaArgs(netip.MustParseAddr("127.0.0.40"), 53, 443)
	args2 := egress.BuildPastaArgs(netip.MustParseAddr("127.0.0.41"), 53, 443)
	if reflect.DeepEqual(args1, args2) {
		t.Error("expected distinct argument lists for distinct addresses, got identical")
	}
}

func TestBuildPastaArgs_Deterministic(t *testing.T) {
	// Same inputs produce byte-identical outputs across calls.
	addr := netip.MustParseAddr("127.0.0.40")
	a := egress.BuildPastaArgs(addr, 53, 443)
	b := egress.BuildPastaArgs(addr, 53, 443)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("non-deterministic output: %#v vs %#v", a, b)
	}
}

func TestBuildPastaArgs_HighPort(t *testing.T) {
	// The port formatter must handle the full uint16 range.
	addr := netip.MustParseAddr("127.0.0.40")
	got := egress.BuildPastaArgs(addr, 65535, 8443)
	want := []string{
		"--splice-only",
		"-T", "127.0.0.40/65535",
		"-T", "127.0.0.40/8443",
		"-U", "127.0.0.40/65535",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}

func TestBuildPastaArgs_PanicsOnIPv6(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on IPv6 address, got none")
		}
	}()
	_ = egress.BuildPastaArgs(netip.MustParseAddr("::1"), 53, 443)
}

func TestBuildPastaArgs_StructuralInvariants(t *testing.T) {
	// The argument list always starts with --splice-only and
	// contains exactly two -T entries and one -U entry.
	addr := netip.MustParseAddr("127.0.0.40")
	args := egress.BuildPastaArgs(addr, 53, 443)
	if len(args) != 7 {
		t.Fatalf("expected exactly 7 arguments, got %d: %#v", len(args), args)
	}
	if args[0] != "--splice-only" {
		t.Errorf("args[0] = %q, want %q", args[0], "--splice-only")
	}
	tCount := 0
	uCount := 0
	for _, a := range args {
		if a == "-T" {
			tCount++
		}
		if a == "-U" {
			uCount++
		}
	}
	if tCount != 2 {
		t.Errorf("expected exactly 2 -T entries, got %d", tCount)
	}
	if uCount != 1 {
		t.Errorf("expected exactly 1 -U entry, got %d", uCount)
	}
}
