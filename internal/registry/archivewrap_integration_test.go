package registry_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

func TestWrapArchiveAsImage_RealSymlink(t *testing.T) {
	eng := testutil.RequireEngine(t)
	ctx := context.Background()

	// A minimal image with ln, pinned by digest (same as paper-1 integration test).
	const img = "cgr.dev/chainguard/go@sha256:fa81487f6395a6fd69d9b4f424683f1f690b9ab55cf2603ed597b0415beafdb9"
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
	// Override entrypoint: chainguard/go has entrypoint=["go"].
	opts.Entrypoint = []string{"ln"}
	// Single shell-free command: create a contained symlink in the volume.
	opts.Cmd = []string{"-s", "sibling", "/work/website"}

	id, code, runErr := eng.ContainerRunHeld(ctx, opts, nil)
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

	// The engine archive prefixes entries with the basename of the archived
	// path (archiving /work yields "work/website", not "/website").
	// A non-zero digest alone does NOT prove the layer is non-empty -- an
	// empty layer also has a valid digest. Wrapping with two different strip
	// prefixes ("" vs "work") must produce different digests, confirming
	// that stripPrefix affects the layer content.
	client := &registry.Client{Engine: eng}
	good, wrapErr := client.WrapOutputsAsImage(ctx, []registry.OutputArchive{
		{Tar: rc, StripPrefix: "", DestPrefix: "site", OutputID: "site"},
	}, "localhost/strike/itest/arch:good")
	if wrapErr != nil {
		t.Fatalf("wrap archive: %v", wrapErr)
	}
	if good.Digest == "" {
		t.Fatal("expected non-zero digest")
	}

	rc2, archErr2 := eng.ContainerArchive(ctx, id, "/work")
	if archErr2 != nil {
		t.Fatalf("re-archive: %v", archErr2)
	}
	defer func() {
		if closeErr := rc2.Close(); closeErr != nil {
			t.Logf("WARN archive close: %v", closeErr)
		}
	}()
	empty, wrapErr2 := client.WrapOutputsAsImage(ctx, []registry.OutputArchive{
		{Tar: rc2, StripPrefix: "work", DestPrefix: "site", OutputID: "site"},
	}, "localhost/strike/itest/arch:basemiss")
	if wrapErr2 != nil {
		t.Fatalf("wrap archive (base prefix): %v", wrapErr2)
	}
	if good.Digest == empty.Digest {
		t.Fatal("stripPrefix had no effect: entries dropped (engine prefix is not the workdir base name)")
	}
}
