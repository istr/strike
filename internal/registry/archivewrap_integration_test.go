package registry_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry"
)

func TestWrapArchiveAsImage_RealSymlink(t *testing.T) {
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("STRIKE_INTEGRATION=0: engine integration test skipped")
	}
	ctx := context.Background()
	eng, err := container.New()
	if err != nil {
		t.Fatalf("connect engine: %v", err)
	}
	if pingErr := eng.Ping(ctx); pingErr != nil {
		t.Fatalf("engine ping: %v", pingErr)
	}

	// A minimal image with ln, pinned by digest (same as paper-1 integration test).
	const img = "cgr.dev/chainguard/go@sha256:4ec098b553c8d74d9f01925578660b2bfcdee4ef45e5ab082250cf9675a0e28b"
	exists, existsErr := eng.ImageExists(ctx, img)
	if existsErr != nil {
		t.Fatalf("image exists: %v", existsErr)
	}
	if !exists {
		if pullErr := eng.ImagePull(ctx, img); pullErr != nil {
			t.Fatalf("pull %s: %v", img, pullErr)
		}
	}

	vol := fmt.Sprintf("strike-itest-arch-%d", clock.Wall().UnixNano())
	if volErr := eng.VolumeCreate(ctx, vol); volErr != nil {
		t.Fatalf("volume create: %v", volErr)
	}
	defer func() {
		if rmErr := eng.VolumeRemove(ctx, vol); rmErr != nil {
			t.Logf("WARN volume remove: %v", rmErr)
		}
	}()

	opts := container.DefaultSecureOpts()
	opts.Image = img
	opts.Workdir = "/work"
	opts.Volume = &container.VolumeMount{Name: vol, Dest: "/work"}
	// Single shell-free command: create a contained symlink in the volume.
	opts.Cmd = []string{"ln", "-s", "sibling", "/work/website"}

	id, code, runErr := eng.ContainerRunHeld(ctx, opts)
	if id != "" {
		defer func() {
			if rmErr := eng.ContainerRemove(ctx, id); rmErr != nil {
				t.Logf("WARN container remove: %v", rmErr)
			}
		}()
	}
	if runErr != nil {
		t.Fatalf("run held: %v", runErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	rc, archErr := eng.ContainerArchive(ctx, id, "/work")
	if archErr != nil {
		t.Fatalf("archive: %v", archErr)
	}
	defer func() {
		if closeErr := rc.Close(); closeErr != nil {
			t.Logf("WARN archive close: %v", closeErr)
		}
	}()

	// stripPrefix is the base name of the archived path; this assertion is
	// what fixes the real engine prefix. If WrapArchiveAsImage produces an
	// empty layer or an error, the prefix assumption is wrong -- report the
	// actual entry names the archive emits.
	client := &registry.Client{Engine: eng}
	tag := "localhost/strike/itest/arch:sym"
	digest, _, wrapErr := client.WrapArchiveAsImage(ctx, rc, "work", "", tag)
	if wrapErr != nil {
		t.Fatalf("wrap archive: %v", wrapErr)
	}
	if digest.IsZero() {
		t.Fatal("expected non-zero digest")
	}
}
