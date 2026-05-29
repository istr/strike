package egress_test

import (
	"reflect"
	"testing"

	"github.com/istr/strike/internal/egress"
)

func TestBuildPastaArgs_HappyPath(t *testing.T) {
	got := egress.BuildPastaArgs(53, 5353, 443, 5354, 0)
	want := []string{
		"--splice-only",
		"-T", "53:5353",
		"-T", "443:5354",
		"-U", "53:5353",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}

func TestBuildPastaArgs_DistinctPerStepPorts(t *testing.T) {
	// Two steps with distinct host-port pairs produce distinct
	// argument lists. Verifies that the function's output
	// discriminates step-to-step.
	args1 := egress.BuildPastaArgs(53, 5353, 443, 5354, 0)
	args2 := egress.BuildPastaArgs(53, 5355, 443, 5356, 0)
	if reflect.DeepEqual(args1, args2) {
		t.Error("expected distinct argument lists for distinct host ports, got identical")
	}
}

func TestBuildPastaArgs_Deterministic(t *testing.T) {
	a := egress.BuildPastaArgs(53, 5353, 443, 5354, 0)
	b := egress.BuildPastaArgs(53, 5353, 443, 5354, 0)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("non-deterministic output: %#v vs %#v", a, b)
	}
}

func TestBuildPastaArgs_HighPort(t *testing.T) {
	// The port formatter must handle the full uint16 range.
	got := egress.BuildPastaArgs(65535, 65535, 443, 65534, 0)
	want := []string{
		"--splice-only",
		"-T", "65535:65535",
		"-T", "443:65534",
		"-U", "65535:65535",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}

func TestBuildPastaArgs_StructuralInvariants(t *testing.T) {
	// The argument list always starts with --splice-only and
	// contains exactly two -T entries and one -U entry, no address.
	args := egress.BuildPastaArgs(53, 5353, 443, 5354, 0)
	if len(args) != 7 {
		t.Fatalf("expected exactly 7 arguments, got %d: %#v", len(args), args)
	}
	if args[0] != "--splice-only" {
		t.Errorf("args[0] = %q, want %q", args[0], "--splice-only")
	}
	tCount, uCount := 0, 0
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

func TestBuildPastaArgs_FrontForward(t *testing.T) {
	got := egress.BuildPastaArgs(53, 5353, 443, 5354, 40000)
	want := []string{
		"--splice-only",
		"-T", "53:5353",
		"-T", "443:5354",
		"-U", "53:5353",
		"-T", "22:40000",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildPastaArgs() = %#v, want %#v", got, want)
	}
}
