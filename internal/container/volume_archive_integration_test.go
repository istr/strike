package container_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
)

// requireEngine returns a live engine, or skips when STRIKE_INTEGRATION=0.
// Engine integration tests run by default; set STRIKE_INTEGRATION=0 to opt
// out in an environment without a running rootless Podman.
func requireEngine(t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("STRIKE_INTEGRATION=0: engine integration test skipped")
	}
	eng, err := container.New()
	if err != nil {
		t.Fatalf("connect engine: %v", err)
	}
	if pingErr := eng.Ping(context.Background()); pingErr != nil {
		t.Fatalf("engine ping: %v", pingErr)
	}
	return eng
}

// TestEngineVolumeArchiveRoundTrip exercises the ADR-035 primitives end to
// end: create a workdir volume, run a held container that writes into it
// under the read-only-root profile, confirm the stopped container survives
// (archive succeeds), read the file back out of the archive, then purge.
//
// If the write step fails with a permission error, that is the workdir
// writability question from ADR-035 surfacing at the engine layer (is a
// named volume at the workdir writable by the keep-id user?), not a defect
// in the primitives -- report it as input for the Phase 1 flow paper.
func TestEngineVolumeArchiveRoundTrip(t *testing.T) {
	eng := requireEngine(t)
	ctx := context.Background()

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

	vol := fmt.Sprintf("strike-itest-%d", clock.Wall().UnixNano())
	if err := eng.VolumeCreate(ctx, vol); err != nil {
		t.Fatalf("volume create: %v", err)
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
	opts.Entrypoint = []string{"touch"}
	opts.Cmd = []string{"/work/marker.txt"}

	id, code, err := eng.ContainerRunHeld(ctx, opts, nil)
	if id != "" {
		defer func() {
			if rmErr := eng.ContainerRemove(ctx, id); rmErr != nil {
				t.Logf("WARN container remove: %v", rmErr)
			}
		}()
	}
	if err != nil {
		t.Fatalf("run held: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a permission error here is the "+
			"workdir-writability residual, not a primitive defect)", code)
	}

	// The held container must still exist (not auto-removed), so archive works.
	rc, err := eng.ContainerArchive(ctx, id, "/work")
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	defer func() {
		if closeErr := rc.Close(); closeErr != nil {
			t.Logf("WARN archive close: %v", closeErr)
		}
	}()

	if !findTarEntry(t, rc, "marker.txt") {
		t.Fatal("marker.txt not found in archive of /work")
	}
}

// findTarEntry scans a tar stream for a regular-file entry whose name
// ends with suffix. The archive may prefix entries with the directory
// name (e.g. "work/marker.txt").
func findTarEntry(t *testing.T, r io.Reader, suffix string) bool {
	t.Helper()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return false
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg && len(hdr.Name) >= len(suffix) &&
			hdr.Name[len(hdr.Name)-len(suffix):] == suffix {
			return true
		}
	}
}

// TestEngineSeedThenRun exercises the ADR-036 seed primitive end to end:
// create a workdir volume, seed a file into it via the archive PUT on the
// created-but-not-started container, run held under the hardened profile,
// then read the workdir back and confirm the seeded file landed before start.
// Mirrors probe 43 (Probe 1).
func TestEngineSeedThenRun(t *testing.T) {
	eng := requireEngine(t)
	ctx := context.Background()

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

	vol := fmt.Sprintf("strike-seed-itest-%d", clock.Wall().UnixNano())
	if err := eng.VolumeCreate(ctx, vol); err != nil {
		t.Fatalf("volume create: %v", err)
	}
	defer func() {
		if rmErr := eng.VolumeRemove(ctx, vol); rmErr != nil {
			t.Logf("WARN volume remove: %v", rmErr)
		}
	}()

	// Seed tar: one regular file, seeded.txt, at the volume root.
	const seedContent = "seeded\n"
	var seedBuf bytes.Buffer
	tw := tar.NewWriter(&seedBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "seeded.txt",
		Mode:     0o644,
		Size:     int64(len(seedContent)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(seedContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	opts := container.DefaultSecureOpts()
	opts.Image = img
	opts.Workdir = "/work"
	opts.Volume = &container.VolumeMount{Name: vol, Dest: "/work"}
	// Read back the seeded file to prove the content landed before start.
	// Writing new files after a pre-start PUT is a separate concern (the
	// archive PUT suppresses the volume's CopyUp, which changes the
	// effective write permissions); the seed primitive's contract is that
	// existing seeded content is present at runtime.
	opts.Entrypoint = []string{"cat"}
	opts.Cmd = []string{"/work/seeded.txt"}

	seeds := []container.Seed{{Path: "/work", Tar: bytes.NewReader(seedBuf.Bytes())}}

	id, code, err := eng.ContainerRunHeld(ctx, opts, seeds)
	if id != "" {
		defer func() {
			if rmErr := eng.ContainerRemove(ctx, id); rmErr != nil {
				t.Logf("WARN container remove: %v", rmErr)
			}
		}()
	}
	if err != nil {
		t.Fatalf("run held: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (seeded content not readable at runtime)", code)
	}

	rc, err := eng.ContainerArchive(ctx, id, "/work")
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	defer func() {
		if closeErr := rc.Close(); closeErr != nil {
			t.Logf("WARN archive close: %v", closeErr)
		}
	}()

	if !findTarEntry(t, rc, "seeded.txt") {
		t.Fatal("seeded.txt not found in /work archive: the seed PUT before start did not land in the volume")
	}
}
