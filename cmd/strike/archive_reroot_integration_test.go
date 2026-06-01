package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// wholeWorkdirNeedsEngine returns a live engine or skips when no engine is
// present or STRIKE_INTEGRATION=0.
func wholeWorkdirNeedsEngine(ctx context.Context, t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("STRIKE_INTEGRATION=0: integration test skipped")
	}
	eng, err := container.New()
	if err != nil {
		t.Skipf("no container engine: %v", err)
	}
	if pingErr := eng.Ping(ctx); pingErr != nil {
		t.Fatalf("engine ping: %v", pingErr)
	}
	return eng
}

// wholeWorkdirEnsureImage pulls an image if not already local.
func wholeWorkdirEnsureImage(ctx context.Context, t *testing.T, eng container.Engine, ref string) {
	t.Helper()
	exists, err := eng.ImageExists(ctx, ref)
	if err != nil {
		t.Fatalf("image exists: %v", err)
	}
	if !exists {
		t.Logf("pulling %s ...", ref)
		if pullErr := eng.ImagePull(ctx, ref); pullErr != nil {
			t.Fatalf("pull %s: %v", ref, pullErr)
		}
	}
}

// TestWholeWorkdirOutput_Integration exercises the path-less directory output
// end to end against a real engine. A path-less output is the "whole workdir
// is the output" form. Before the archiveReroot fix, the mountpoint archive
// wrapped to an empty layer because the strip prefix matched zero entries.
//
// The test seeds a mixed tree (top-level file and nested subdirectory) into
// the workdir volume, runs a held container that exits 0, then archives the
// workdir mountpoint, wraps it via WrapArchiveAsImage with the archiveReroot
// strip/dest, saves the resulting image, extracts the single layer, and
// asserts the whole workdir is present under the output name.
func TestWholeWorkdirOutput_Integration(t *testing.T) {
	ctx := context.Background()
	eng := wholeWorkdirNeedsEngine(ctx, t)

	const img = "cgr.dev/chainguard/go@sha256:4ec098b553c8d74d9f01925578660b2bfcdee4ef45e5ab082250cf9675a0e28b"
	wholeWorkdirEnsureImage(ctx, t, eng, img)

	vol := fmt.Sprintf("strike-workdir-itest-%d", clock.Wall().UnixNano())
	if err := eng.VolumeCreate(ctx, vol); err != nil {
		t.Fatalf("volume create: %v", err)
	}
	defer func() {
		if rmErr := eng.VolumeRemove(ctx, vol); rmErr != nil {
			t.Logf("WARN volume remove: %v", rmErr)
		}
	}()

	// Build seed tar: a top-level file and a nested subdirectory with a file.
	var seedBuf bytes.Buffer
	tw := tar.NewWriter(&seedBuf)
	seedFiles := []struct {
		name    string
		content string
	}{
		{"package.json", "{}"},
		{"node_modules/pkg/index.js", "x"},
	}
	for _, f := range seedFiles {
		if err := tw.WriteHeader(&tar.Header{
			Name:     f.name,
			Mode:     0o644,
			Size:     int64(len(f.content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	opts := container.DefaultSecureOpts()
	opts.Image = img
	opts.Workdir = "/out"
	opts.Volume = &container.VolumeMount{Name: vol, Dest: "/out"}
	opts.Entrypoint = []string{"cat"}
	opts.Cmd = []string{"/dev/null"}

	seeds := []container.Seed{{Path: "/out", Tar: bytes.NewReader(seedBuf.Bytes())}}

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
		t.Fatalf("exit code = %d, want 0", code)
	}

	// Path-less directory output: the whole workdir is the output.
	out := lane.OutputSpec{Name: "node_modules", Type: "directory"}
	archivePath, strip, dest := archiveReroot("/out", out)

	stream, archErr := eng.ContainerArchive(ctx, id, archivePath)
	if archErr != nil {
		t.Fatalf("archive: %v", archErr)
	}

	tag := fmt.Sprintf("localhost/strike/workdir-itest:%d", clock.Wall().UnixNano())
	regClient := &registry.Client{Engine: eng}
	digest, size, wrapErr := regClient.WrapArchiveAsImage(ctx, stream, strip, dest, tag)
	if wrapErr != nil {
		t.Fatalf("wrap: %v", wrapErr)
	}
	if size == 0 {
		t.Fatal("layer size = 0: the whole-workdir output wrapped to an empty layer")
	}
	t.Logf("wrapped: digest=%s size=%d tag=%s", digest, size, tag)

	saved, saveErr := registry.SaveImage(ctx, eng, tag)
	if saveErr != nil {
		t.Fatalf("save image: %v", saveErr)
	}
	destDir := t.TempDir()
	if extractErr := registry.ExtractSingleLayer(saved, destDir); extractErr != nil {
		t.Fatalf("extract: %v", extractErr)
	}

	// The whole workdir must be re-rooted under the output name ("node_modules").
	wantFiles := []string{
		"node_modules/node_modules/pkg/index.js",
		"node_modules/package.json",
	}
	for _, want := range wantFiles {
		full := filepath.Join(destDir, want)
		if _, statErr := os.Stat(full); statErr != nil {
			t.Errorf("expected file %s not found: %v", want, statErr)
		}
	}
}
