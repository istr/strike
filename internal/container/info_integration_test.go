package container_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
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

	checks := []struct {
		field string
		got   any
		path  []string
	}{
		{"Runtime.Rootless", id.Runtime.Rootless, []string{"host", "security", "rootless"}},
		{"Runtime.SELinux", id.Runtime.SELinux, []string{"host", "security", "selinuxEnabled"}},
		{"Runtime.AppArmor", id.Runtime.AppArmor, []string{"host", "security", "apparmorEnabled"}},
		{"Runtime.APIVersion", id.Runtime.APIVersion, []string{"version", "APIVersion"}},
		{"Runtime.Version", id.Runtime.Version, []string{"version", "Version"}},
	}

	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			raw, ok := navPath(m, c.path...)
			if !ok {
				t.Fatalf("raw response missing path %v -- schema drift?", c.path)
			}
			if !equalValue(raw, c.got) {
				t.Errorf("typed %s = %v, raw %v = %v -- schema drift?",
					c.field, c.got, strings.Join(c.path, "."), raw)
			}
		})
	}
}

// navPath traverses nested map[string]any by key sequence.
func navPath(m map[string]any, path ...string) (any, bool) {
	cur := any(m)
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := mm[k]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// equalValue compares a raw JSON value (from map[string]any) to a typed Go value.
func equalValue(raw, typed any) bool {
	switch t := typed.(type) {
	case bool:
		r, ok := raw.(bool)
		return ok && r == t
	case string:
		r, ok := raw.(string)
		return ok && r == t
	default:
		return fmt.Sprintf("%v", raw) == fmt.Sprintf("%v", typed)
	}
}
