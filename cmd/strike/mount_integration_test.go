package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

// Digest-pinned images matching test/integration/helpers_test.go.
// Redeclared here because that package (integration_test) is not
// importable from cmd/strike (package main).
const (
	mountGoImage = "cgr.dev/chainguard/go@sha256:7596cc2ec314f54001ca15753e5ac11e9e10106fde96cd24f6a886a2eb770dd8"
)

// mountEnsureImage pulls an image if not already local.
func mountEnsureImage(t *testing.T, engine container.Engine, ref string) {
	t.Helper()
	ctx := context.Background()
	exists, err := engine.ImageExists(ctx, ref)
	if err != nil {
		t.Fatalf("image exists check: %v", err)
	}
	if !exists {
		t.Logf("pulling %s ...", ref)
		if pullErr := engine.ImagePull(ctx, ref); pullErr != nil {
			t.Fatalf("pull %s: %v", ref, pullErr)
		}
	}
}

// TestOutsideWorkdirMount_INTEGRATION exercises the outside-workdir
// read-only image mount and the no-workdir consumer end to end against a
// live rootless podman, confirming that a local producer tag resolves as
// an image_volumes Source in the actual mount-construction path.
func TestOutsideWorkdirMount_INTEGRATION(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()
	mountEnsureImage(t, engine, mountGoImage)

	const marker = "STRIKE-E2E-PROOF-IMAGE-MOUNT-20260528"

	// Build a producer image containing src/marker.txt.
	tarBytes, err := regtest.BuildMultiFileImageTar(map[string][]byte{
		"src/marker.txt": []byte(marker),
		"src/extra.txt":  []byte("extra"),
	})
	if err != nil {
		t.Fatalf("build producer image: %v", err)
	}
	producerTag := fmt.Sprintf("localhost/strike/mount-itest:%d", clock.Wall().UnixNano())
	id, loadErr := engine.ImageLoad(ctx, bytes.NewReader(tarBytes))
	if loadErr != nil {
		t.Fatalf("load producer image: %v", loadErr)
	}
	if tagErr := engine.ImageTag(ctx, id, producerTag); tagErr != nil {
		t.Fatalf("tag producer image as %s: %v", producerTag, tagErr)
	}
	t.Logf("producer image loaded and tagged: %s", producerTag)

	t.Run("directory_mount_outside_workdir", func(t *testing.T) {
		// Consumer: workdir /build (writable volume), input src
		// mounted read-only at /src via image_volumes. Reads
		// /src/marker.txt and outputs to stdout.
		volName := fmt.Sprintf("strike-mount-itest-a-%d", clock.Wall().UnixNano())
		if vErr := engine.VolumeCreate(ctx, volName); vErr != nil {
			t.Fatalf("volume create: %v", vErr)
		}
		defer func() {
			if rmErr := engine.VolumeRemove(ctx, volName); rmErr != nil {
				t.Logf("WARN volume remove: %v", rmErr)
			}
		}()

		var stdout, stderr bytes.Buffer
		opts := container.DefaultSecureOpts()
		opts.Image = mountGoImage
		opts.Workdir = "/build"
		opts.Volume = &container.VolumeMount{Name: volName, Dest: "/build"}
		opts.ImageVolumes = []container.ImageVolume{{
			Source:      producerTag,
			Destination: "/src",
			SubPath:     "src",
			ReadWrite:   false,
		}}
		opts.Entrypoint = []string{"cat"}
		opts.Cmd = []string{"/src/marker.txt"}
		opts.Stdout = &stdout
		opts.Stderr = &stderr

		exitCode, runErr := engine.ContainerRun(ctx, opts)
		if runErr != nil {
			t.Fatalf("consumer run: %v\nstderr: %s", runErr, stderr.String())
		}
		if exitCode != 0 {
			t.Fatalf("consumer exit %d\nstdout: %s\nstderr: %s",
				exitCode, stdout.String(), stderr.String())
		}
		got := strings.TrimSpace(stdout.String())
		if got != marker {
			t.Errorf("consumer stdout = %q, want %q "+
				"(mount did not deliver producer content)", got, marker)
		}
		t.Logf("confirmed: local tag %q resolved as image_volumes Source "+
			"under rootless podman", producerTag)
	})

	t.Run("no_workdir_consumer", func(t *testing.T) {
		// Consumer: no workdir, no outputs, input src mounted at /in.
		// Reads /in/marker.txt and exits 0.
		var stdout, stderr bytes.Buffer
		opts := container.DefaultSecureOpts()
		opts.Image = mountGoImage
		opts.ImageVolumes = []container.ImageVolume{{
			Source:      producerTag,
			Destination: "/in",
			SubPath:     "src",
			ReadWrite:   false,
		}}
		opts.Entrypoint = []string{"cat"}
		opts.Cmd = []string{"/in/marker.txt"}
		opts.Stdout = &stdout
		opts.Stderr = &stderr

		exitCode, runErr := engine.ContainerRun(ctx, opts)
		if runErr != nil {
			t.Fatalf("consumer run: %v\nstderr: %s", runErr, stderr.String())
		}
		if exitCode != 0 {
			t.Fatalf("consumer exit %d (no-workdir consumer with image mount failed)\n"+
				"stdout: %s\nstderr: %s", exitCode, stdout.String(), stderr.String())
		}
		t.Logf("no-workdir consumer completed: image-volume mount with " +
			"no writable volume reached the engine successfully")
	})
}
