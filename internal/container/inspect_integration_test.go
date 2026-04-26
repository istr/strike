package container_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
)

const inspectTestImage = "cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b"

// needsIntegrationEngine returns a ready engine or skips the test.
func needsIntegrationEngine(ctx context.Context, t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	eng, err := container.New()
	if err != nil {
		t.Skipf("no container engine: %v", err)
	}
	if pingErr := eng.Ping(ctx); pingErr != nil {
		t.Fatalf("Ping: %v", pingErr)
	}
	return eng
}

// ensureImageLocal pulls an image if it is not in the local store.
func ensureImageLocal(ctx context.Context, t *testing.T, eng container.Engine, ref string) {
	t.Helper()
	exists, err := eng.ImageExists(ctx, ref)
	if err != nil {
		t.Fatalf("ImageExists: %v", err)
	}
	if !exists {
		t.Logf("pulling %s ...", ref)
		if pullErr := eng.ImagePull(ctx, ref); pullErr != nil {
			t.Fatalf("ImagePull: %v", pullErr)
		}
	}
}

// checkVolatilePresence verifies that volatile fields exist in the raw
// response without comparing values (they change between runs).
func checkVolatilePresence(t *testing.T, m map[string]any, paths [][]string) {
	t.Helper()
	for _, p := range paths {
		t.Run("presence:"+joinPath(p), func(t *testing.T) {
			if _, ok := navPath(m, p...); !ok {
				t.Errorf("raw response missing volatile path %v -- schema drift?", p)
			}
		})
	}
}

func TestIntegrationContainerInspectSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*clock.Second)
	defer cancel()

	eng := needsIntegrationEngine(ctx, t)
	ensureImageLocal(ctx, t, eng, inspectTestImage)

	// Create a container but do not start it. "created" state is
	// deterministic and avoids timing-sensitive fields.
	id, err := container.PodmanContainerCreate(ctx, eng, container.RunOpts{
		Image: inspectTestImage,
		Cmd:   []string{"/nonexistent"}, // never executed
	})
	if err != nil {
		t.Fatalf("ContainerCreate: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*clock.Second)
		defer ccancel()
		if rmErr := container.PodmanContainerRemove(cctx, eng, id); rmErr != nil {
			t.Logf("cleanup: ContainerRemove(%s): %v", id, rmErr)
		}
	})

	info, err := container.PodmanContainerInspect(ctx, eng, id)
	if err != nil {
		t.Fatalf("ContainerInspect: %v", err)
	}

	body, err := container.PodmanRawGet(ctx, eng, "/containers/"+id+"/json")
	if err != nil {
		t.Fatalf("rawGet inspect: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Scalar fields extracted by the typed decoder.
	// TODO(07-C): extend to collection-typed fields (Config.Env,
	// Config.Labels, Mounts, NetworkSettings.Ports) once the drift
	// helper supports element-wise comparison.
	checks := []diffCheck{
		{"ID", info.ID, []string{"Id"}},
		{"Image", info.Image, []string{"Image"}},
		{"State.Status", info.State.Status, []string{"State", "Status"}},
		{"State.Running", info.State.Running, []string{"State", "Running"}},
		{"State.ExitCode", info.State.ExitCode, []string{"State", "ExitCode"}},
		{"Config.WorkingDir", info.Config.WorkingDir, []string{"Config", "WorkingDir"}},
		{"Config.User", info.Config.User, []string{"Config", "User"}},
	}
	runDriftChecks(t, m, checks)

	// LogPath is only present after a container has been started, so
	// it is excluded from the volatile list for "created" containers.
	checkVolatilePresence(t, m, [][]string{
		{"Created"},
		{"State", "StartedAt"},
		{"State", "FinishedAt"},
		{"State", "Pid"},
		{"ResolvConfPath"},
		{"HostnamePath"},
		{"HostsPath"},
	})
}
