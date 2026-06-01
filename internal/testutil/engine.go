package testutil

import (
	"os"
	"testing"

	"github.com/istr/strike/internal/container"
)

// RequireEngine returns a live container.Engine for an integration test.
//
// STRIKE_INTEGRATION=0 skips the test -- the sanctioned opt-out. Otherwise the
// engine is a prerequisite: an unreachable or unresponsive engine is a hard
// failure carrying the opt-out hint, so the operator either provides the
// engine or opts out explicitly instead of reading a bare error.
func RequireEngine(t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	eng, err := container.New()
	if err != nil {
		t.Fatalf("container engine unreachable (%v); set STRIKE_INTEGRATION=0 to skip integration tests", err)
	}
	if pingErr := eng.Ping(t.Context()); pingErr != nil {
		t.Fatalf("container engine not responding (%v); set STRIKE_INTEGRATION=0 to skip integration tests", pingErr)
	}
	return eng
}
