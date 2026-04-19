package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

const testAlgoSHA256 = "sha256"

// newTestRC creates a minimal runContext with the given engine for testing.
func newTestRC(t *testing.T, engine *mockEngine) *runContext {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Logf("close root: %v", err)
		}
	})
	return &runContext{
		ctx:       context.Background(),
		lane:      &lane.Lane{Registry: "localhost:5555/test"},
		dag:       &lane.DAG{Steps: map[string]*lane.Step{}},
		regClient: &registry.Client{Engine: engine},
		engine:    engine,
		state:     newRunState(),
		laneState: lane.NewState(),
		laneRoot:  root,
		laneDir:   dir,
	}
}

// --------------------------------------------------------------------------.
// buildInputMounts
// --------------------------------------------------------------------------.

func TestBuildInputMounts_Single(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "compile", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: "/out/binary"}},
			},
			{
				Name: "test", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "bin", From: "compile.bin", Mount: "/input/binary"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "binary"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc.state.outputDirs["compile"] = outDir

	mounts := rc.buildInputMounts(rc.dag.Steps["test"])
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Container != "/input/binary" {
		t.Errorf("mount container = %q, want /input/binary", mounts[0].Container)
	}
	if !mounts[0].ReadOnly {
		t.Error("expected mount to be read-only")
	}
	if !strings.HasSuffix(mounts[0].Host, "binary") {
		t.Errorf("host path should end in 'binary', got %q", mounts[0].Host)
	}
}

func TestBuildInputMounts_Multiple(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "s1", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "a", Type: "file", Path: "/out/a.tar"}},
			},
			{
				Name: "s2", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "b", Type: "file", Path: "/out/b.tar"}},
			},
			{
				Name: "consumer", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{Name: "a", From: "s1.a", Mount: "/in/a"},
					{Name: "b", From: "s2.b", Mount: "/in/b"},
				},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	dir1, dir2 := t.TempDir(), t.TempDir()
	writeTestFile(t, filepath.Join(dir1, "a.tar"), "a")
	writeTestFile(t, filepath.Join(dir2, "b.tar"), "b")
	rc.state.outputDirs["s1"] = dir1
	rc.state.outputDirs["s2"] = dir2

	mounts := rc.buildInputMounts(rc.dag.Steps["consumer"])
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
}

// --------------------------------------------------------------------------.
// buildSourceMounts
// --------------------------------------------------------------------------.

func TestBuildSourceMounts(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	step := &lane.Step{
		Sources: []lane.SourceRef{
			{Path: "src", Mount: "/src"},
		},
	}

	mounts := rc.buildSourceMounts(step)
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Container != "/src" {
		t.Errorf("container = %q, want /src", mounts[0].Container)
	}
	if !mounts[0].ReadOnly {
		t.Error("expected read-only")
	}
	if !strings.HasSuffix(mounts[0].Host, "src") {
		t.Errorf("host should end in 'src', got %q", mounts[0].Host)
	}
}

// --------------------------------------------------------------------------.
// guardUnsignedImages
// --------------------------------------------------------------------------.

func TestGuardUnsignedImages_NoNetwork(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "publish", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{Name: "img", From: "pack.img", Mount: "/in/img"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)
	if err := rc.guardUnsignedImages(rc.dag.Steps["publish"], "test"); err != nil {
		t.Fatalf("no-network step should not error: %v", err)
	}
}

func TestGuardUnsignedImages_SignedOK(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "publish", Image: "img", Args: []string{}, Env: map[string]string{},
				Network: true,
				Inputs:  []lane.InputRef{{Name: "img", From: "pack.img", Mount: "/in/img"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)
	rc.state.ociSigned["pack/img"] = true

	if err := rc.guardUnsignedImages(rc.dag.Steps["publish"], "test"); err != nil {
		t.Fatalf("signed image should be OK: %v", err)
	}
}

func TestGuardUnsignedImages_UnsignedError(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "publish", Image: "img", Args: []string{}, Env: map[string]string{},
				Network: true,
				Inputs:  []lane.InputRef{{Name: "img", From: "pack.img", Mount: "/in/img"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)
	// ociSigned not set for "pack/img"

	err := rc.guardUnsignedImages(rc.dag.Steps["publish"], "test")
	if err == nil {
		t.Fatal("expected error for unsigned image with network")
	}
	if !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("error should mention 'unsigned': %v", err)
	}
}

func TestGuardUnsignedImages_NonImageInput(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "compile", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: "/out/bin"}},
			},
			{
				Name: "run", Image: "img", Args: []string{}, Env: map[string]string{},
				Network: true,
				Inputs:  []lane.InputRef{{Name: "bin", From: "compile.bin", Mount: "/in/bin"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	if err := rc.guardUnsignedImages(rc.dag.Steps["run"], "test"); err != nil {
		t.Fatalf("non-image input should be OK: %v", err)
	}
}

// --------------------------------------------------------------------------.
// computeSpecHash
// --------------------------------------------------------------------------.

func TestComputeSpecHash_Deterministic(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})

	step := &lane.Step{
		Args: []string{"build"},
		Env:  map[string]string{"K": "V"},
	}

	h1, tag1, err := rc.computeSpecHash(step, "step1", lane.MustParseDigest("sha256:abc"))
	if err != nil {
		t.Fatal(err)
	}
	h2, tag2, err := rc.computeSpecHash(step, "step1", lane.MustParseDigest("sha256:abc"))
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("hashes differ: %s vs %s", h1, h2)
	}
	if tag1 != tag2 {
		t.Errorf("tags differ: %s vs %s", tag1, tag2)
	}
	if h1.Algorithm != testAlgoSHA256 {
		t.Errorf("hash should have sha256 algorithm, got %q", h1.Algorithm)
	}
}

func TestComputeSpecHash_ChangesWithImageDigest(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	step := &lane.Step{Args: []string{"build"}, Env: map[string]string{}}

	h1, _, err := rc.computeSpecHash(step, "s", lane.MustParseDigest("sha256:aaa"))
	if err != nil {
		t.Fatal(err)
	}
	// Reset specHashes to avoid accumulation from prior call.
	rc.state.specHashes = map[string]lane.Digest{}
	h2, _, err := rc.computeSpecHash(step, "s", lane.MustParseDigest("sha256:bbb"))
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("different image digests should produce different hashes")
	}
}

func TestComputeSpecHash_WithSources(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})

	// Create a source file in the lane dir.
	srcDir := filepath.Join(rc.laneDir, "src")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Args:    []string{"build"},
		Env:     map[string]string{},
		Sources: []lane.SourceRef{{Path: "src", Mount: "/src"}},
	}

	h, _, err := rc.computeSpecHash(step, "build", lane.MustParseDigest("sha256:img"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Algorithm != testAlgoSHA256 {
		t.Errorf("hash should have sha256 algorithm, got %q", h.Algorithm)
	}
}

// --------------------------------------------------------------------------.
// checkCache
// --------------------------------------------------------------------------.

func TestCheckCache_Miss(t *testing.T) {
	eng := &mockEngine{imageExistsRV: false}
	rc := newTestRC(t, eng)

	hit := rc.checkCache(context.Background(), "step1", "step1", "localhost:5555/test:step1-abc", lane.MustParseDigest("sha256:full"))
	if hit {
		t.Error("expected cache miss")
	}
}

func TestCheckCache_Hit(t *testing.T) {
	eng := &mockEngine{
		imageExistsRV: true,
		inspectRV: &container.ImageInfo{
			Annotations: map[string]string{
				"dev.strike.cache-key": "sha256:fullhash",
			},
		},
	}
	rc := newTestRC(t, eng)

	hit := rc.checkCache(context.Background(), "step1", "step1", "localhost:5555/test:step1-abc", lane.MustParseDigest("sha256:fullhash"))
	if !hit {
		t.Error("expected cache hit")
	}
	if rc.state.outputDirs["step1"] == "" {
		t.Error("outputDirs should be set on cache hit")
	}
}

// --------------------------------------------------------------------------.
// resolveImageDigest
// --------------------------------------------------------------------------.

func TestResolveImageDigest_FromRef(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	step := &lane.Step{Image: "docker.io/lib/golang@sha256:abcdef1234567890"}

	digest, err := rc.resolveImageDigest(context.Background(), step, "test")
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "sha256:abcdef1234567890" {
		t.Errorf("digest = %q, want sha256:abcdef1234567890", digest.String())
	}
}

func TestResolveImageDigest_FromInspect(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: "sha256:inspected1234567890",
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{Image: "docker.io/lib/golang:1.22"}

	digest, err := rc.resolveImageDigest(context.Background(), step, "test")
	if err != nil {
		t.Fatal(err)
	}
	if digest.Algorithm != testAlgoSHA256 {
		t.Errorf("expected sha256 algorithm, got %q", digest.Algorithm)
	}
}

func TestResolveImageDigest_ImageFrom(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFrom: &lane.ImageFrom{Step: "pack", Output: "img"},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)
	rc.state.ociDigests["pack/img"] = lane.MustParseDigest("sha256:abcdef123456789000")

	step := rc.dag.Steps["run"]
	digest, err := rc.resolveImageDigest(context.Background(), step, "test")
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "sha256:abcdef123456789000" {
		t.Errorf("digest = %q, want sha256:abcdef123456789000", digest.String())
	}
	if !strings.HasPrefix(step.Image, "localhost/strike:") {
		t.Errorf("step.Image should be set to localhost/strike:..., got %q", step.Image)
	}
}

func TestResolveImageDigest_ImageFromMissing(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFrom: &lane.ImageFrom{Step: "pack", Output: "img"},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	_, err := rc.resolveImageDigest(context.Background(), rc.dag.Steps["run"], "test")
	if err == nil {
		t.Fatal("expected error for missing digest")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error should mention 'not available': %v", err)
	}
}

// --------------------------------------------------------------------------.
// resolvePackInputPaths
// --------------------------------------------------------------------------.

func TestResolvePackInputPaths(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "compile", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: "/out/binary"}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "compile.bin", Dest: "/app"}},
				},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	outDir := t.TempDir()
	writeTestFile(t, filepath.Join(outDir, "binary"), "bin")
	rc.state.outputDirs["compile"] = outDir

	paths, err := rc.resolvePackInputPaths(rc.dag.Steps["pack"], "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := paths["/app"]; !ok {
		t.Fatal("expected '/app' in paths")
	}
	if !strings.HasSuffix(paths["/app"], "binary") {
		t.Errorf("path should end in 'binary', got %q", paths["/app"])
	}
}

// --------------------------------------------------------------------------.
// resolvePackSecrets
// --------------------------------------------------------------------------.

func TestResolvePackSecrets_FromEnv(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	rc.lane.Secrets = map[string]lane.SecretSource{ //nolint:gosec // G101: test fixture, not real credentials
		"cosign_key":      "env://STRIKE_TEST_KEY",
		"cosign_password": "env://STRIKE_TEST_PWD",
	}

	t.Setenv("STRIKE_TEST_KEY", "key-data")
	t.Setenv("STRIKE_TEST_PWD", "pwd-data")

	step := &lane.Step{
		Secrets: []lane.SecretRef{
			{Name: "cosign_key"},
			{Name: "cosign_password"},
		},
	}

	key, pwd, err := rc.resolvePackSecrets(step, "test")
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "key-data" {
		t.Errorf("key = %q, want key-data", key)
	}
	if string(pwd) != "pwd-data" {
		t.Errorf("pwd = %q, want pwd-data", pwd)
	}
}

func TestResolvePackSecrets_MissingDef(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	rc.lane.Secrets = map[string]lane.SecretSource{}

	step := &lane.Step{
		Secrets: []lane.SecretRef{{Name: "cosign_key"}},
	}

	_, _, err := rc.resolvePackSecrets(step, "test")
	if err == nil {
		t.Fatal("expected error for missing secret definition")
	}
	if !strings.Contains(err.Error(), "not defined") {
		t.Errorf("error should mention 'not defined': %v", err)
	}
}

// --------------------------------------------------------------------------.
// pushAndReport
// --------------------------------------------------------------------------.

func TestPushAndReport_NoImage(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	step := &lane.Step{
		Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: "/out/bin"}},
	}
	if err := rc.pushAndReport(context.Background(), step, "test", "tag"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushAndReport_ImagePushError(t *testing.T) {
	eng := &mockEngine{pushErr: fmt.Errorf("network down")}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
	}
	err := rc.pushAndReport(context.Background(), step, "test", "tag")
	if err == nil {
		t.Fatal("expected error on push failure")
	}
	if !strings.Contains(err.Error(), "push failed") {
		t.Errorf("error should mention 'push failed': %v", err)
	}
}

func TestPushAndReport_ImagePushOK(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: "/out/img.tar"}},
	}
	if err := rc.pushAndReport(context.Background(), step, "test", "tag"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --------------------------------------------------------------------------.
// runStep (integration-level, error paths)
// --------------------------------------------------------------------------.

func TestRunStep_InvalidTimeout(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	rc.dag.Steps["bad"] = &lane.Step{
		Timeout: "not-a-duration",
		Image:   "img@sha256:abc",
		Args:    []string{"run"},
		Env:     map[string]string{},
	}

	err := rc.runStep("bad")
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), "invalid timeout") {
		t.Errorf("error should mention 'invalid timeout': %v", err)
	}
}

// --------------------------------------------------------------------------.
// executor.Mount field checks
// --------------------------------------------------------------------------.

func TestBuildSourceMounts_HostPathJoined(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	step := &lane.Step{
		Sources: []lane.SourceRef{
			{Path: "a/b", Mount: "/m"},
		},
	}
	mounts := rc.buildSourceMounts(step)
	want := filepath.Join(rc.laneDir, "a/b")
	if mounts[0].Host != want {
		t.Errorf("host = %q, want %q", mounts[0].Host, want)
	}
}

// --------------------------------------------------------------------------.
// newRunState
// --------------------------------------------------------------------------.

func TestNewRunState(t *testing.T) {
	s := newRunState()
	if s.specHashes == nil || s.outputDirs == nil || s.ociDigests == nil || s.ociSigned == nil {
		t.Fatal("all maps should be initialized")
	}
}

// writeTestFile is a helper that writes content to path, failing the test on error.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
