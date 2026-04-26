package container_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
)

func TestIntegrationInfoSchema(t *testing.T) {
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}

	eng, err := container.New()
	if err != nil {
		t.Skipf("no container engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*clock.Second)
	defer cancel()

	if pingErr := eng.Ping(ctx); pingErr != nil {
		t.Fatalf("Ping: %v", pingErr)
	}
	if infoErr := eng.Info(ctx); infoErr != nil {
		t.Fatalf("Info: %v", infoErr)
	}

	id := eng.Identity()
	if id == nil || id.Runtime == nil {
		t.Fatal("expected non-nil Identity with Runtime after Info")
	}

	body, err := container.PodmanRawGet(ctx, eng, "/info")
	if err != nil {
		t.Fatalf("rawGet /info: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	checks := []diffCheck{
		{"Runtime.Rootless", id.Runtime.Rootless, []string{"host", "security", "rootless"}},
		{"Runtime.SELinux", id.Runtime.SELinux, []string{"host", "security", "selinuxEnabled"}},
		{"Runtime.AppArmor", id.Runtime.AppArmor, []string{"host", "security", "apparmorEnabled"}},
		{"Runtime.APIVersion", id.Runtime.APIVersion, []string{"version", "APIVersion"}},
		{"Runtime.Version", id.Runtime.Version, []string{"version", "Version"}},
	}
	runDriftChecks(t, m, checks)
}
