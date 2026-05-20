package capsule_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/istr/strike/internal/capsule"
)

func TestAllocateAddresses_StartsAt40(t *testing.T) {
	m, err := capsule.AllocateAddresses([]string{"first"})
	if err != nil {
		t.Fatalf("AllocateAddresses: %v", err)
	}
	want := netip.MustParseAddr("127.0.0.40")
	if got := m["first"]; got != want {
		t.Errorf("first = %s, want %s", got, want)
	}
}

func TestAllocateAddresses_SequentialInInputOrder(t *testing.T) {
	names := []string{"a", "b", "c"}
	m, err := capsule.AllocateAddresses(names)
	if err != nil {
		t.Fatalf("AllocateAddresses: %v", err)
	}
	wants := map[string]string{
		"a": "127.0.0.40",
		"b": "127.0.0.41",
		"c": "127.0.0.42",
	}
	for name, want := range wants {
		if got := m[name].String(); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
}

func TestAllocateAddresses_Deterministic(t *testing.T) {
	names := []string{"build", "test", "deploy"}
	a, err := capsule.AllocateAddresses(names)
	if err != nil {
		t.Fatalf("AllocateAddresses: %v", err)
	}
	b, err := capsule.AllocateAddresses(names)
	if err != nil {
		t.Fatalf("AllocateAddresses: %v", err)
	}
	for name := range a {
		if a[name] != b[name] {
			t.Errorf("non-deterministic for %s: %s vs %s", name, a[name], b[name])
		}
	}
}

func TestAllocateAddresses_AllDistinct(t *testing.T) {
	names := make([]string, 100)
	for i := range names {
		names[i] = fmt.Sprintf("step-%03d", i)
	}
	m, err := capsule.AllocateAddresses(names)
	if err != nil {
		t.Fatalf("AllocateAddresses: %v", err)
	}
	seen := make(map[netip.Addr]struct{}, len(m))
	for _, addr := range m {
		if _, dup := seen[addr]; dup {
			t.Errorf("duplicate address %s", addr)
		}
		seen[addr] = struct{}{}
	}
	if len(seen) != 100 {
		t.Errorf("expected 100 distinct addresses, got %d", len(seen))
	}
}

func TestAllocateAddresses_Exhaustion(t *testing.T) {
	names := make([]string, 216) // 215 available + 1
	for i := range names {
		names[i] = fmt.Sprintf("step-%03d", i)
	}
	if _, err := capsule.AllocateAddresses(names); err == nil {
		t.Error("expected exhaustion error, got nil")
	}
}

func TestAllocateAddresses_Empty(t *testing.T) {
	m, err := capsule.AllocateAddresses(nil)
	if err != nil {
		t.Fatalf("AllocateAddresses(nil): %v", err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}
