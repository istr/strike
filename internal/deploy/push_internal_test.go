package deploy

import (
	"strings"
	"testing"
)

// TestNewRegistryTransport_RejectsNilDialer pins that the push transport
// refuses a missing lane dialer at construction, the way the capsule and
// mediator constructors do. Without the check a Deployer built without one
// fails inside the dial callback, long after the point that can report it.
func TestNewRegistryTransport_RejectsNilDialer(t *testing.T) {
	_, _, err := newRegistryTransport(DeployRegistryForTest().Target, nil)
	if err == nil {
		t.Fatal("expected an error for a nil dialer, got nil")
	}
	if !strings.Contains(err.Error(), "dialer required") {
		t.Errorf("error %q must report the missing dialer", err)
	}
}
