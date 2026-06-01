package container_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/testutil"
)

func TestIntegrationInfoSchema(t *testing.T) {
	eng := testutil.RequireEngine(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*clock.Second)
	defer cancel()
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
