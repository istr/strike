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
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/transport"
)

const testAlgoSHA256 = "sha256"

const (
	testFullDigestHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	testFullDigest    = "sha256:" + testFullDigestHex
)

const (
	testCosignKeyRef    = "env://STRIKE_TEST_KEY"
	testCosignUnlockRef = "env://STRIKE_TEST_PWD"
)

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
				Name: "compile", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))}},
			},
			{
				Name: "test", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "compile.bin", Mount: "/input/binary"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	// Register the artifact and spec hash for the producing step.
	compileDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	if err := rc.laneState.Register("compile", "bin", lane.Artifact{
		Type: "file", Digest: compileDigest,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["compile"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	// Build a test OCI tar with a "binary" file inside.
	tarBytes, _, err := regtest.BuildImageTar("binary", []byte("data"))
	if err != nil {
		t.Fatalf("BuildImageTar: %v", err)
	}
	tag := registry.WrapTag(rc.lane.LaneID, "compile", rc.state.specHashes["compile"])
	eng.saveTars = map[string][]byte{tag: tarBytes}

	scratchDir := t.TempDir()
	mounts, mountErr := rc.buildInputMounts(context.Background(), rc.dag.Steps["test"], scratchDir)
	if mountErr != nil {
		t.Fatalf("buildInputMounts: %v", mountErr)
	}
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
				Name: "s1", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "a", Type: "file", Path: lane.Ptr(lane.RelPath("a.tar"))}},
			},
			{
				Name: "s2", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "b", Type: "file", Path: lane.Ptr(lane.RelPath("b.tar"))}},
			},
			{
				Name: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "s1.a", Mount: "/in/a"},
					{From: "s2.b", Mount: "/in/b"},
				},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	// Register artifacts and spec hashes for both producing steps.
	d1 := lane.MustParseDigest("sha256:aaaa111122223333000000000000000000000000000000000000000000000000")
	d2 := lane.MustParseDigest("sha256:bbbb444455556666000000000000000000000000000000000000000000000000")
	if err := rc.laneState.Register("s1", "a", lane.Artifact{Type: "file", Digest: d1}); err != nil {
		t.Fatal(err)
	}
	if err := rc.laneState.Register("s2", "b", lane.Artifact{Type: "file", Digest: d2}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["s1"] = lane.MustParseDigest("sha256:2222222222222222000000000000000000000000000000000000000000000000")
	rc.state.specHashes["s2"] = lane.MustParseDigest("sha256:3333333333333333000000000000000000000000000000000000000000000000")

	// Build test image tars for both steps.
	tar1, _, err := regtest.BuildImageTar("a.tar", []byte("a"))
	if err != nil {
		t.Fatalf("BuildImageTar s1: %v", err)
	}
	tar2, _, err := regtest.BuildImageTar("b.tar", []byte("b"))
	if err != nil {
		t.Fatalf("BuildImageTar s2: %v", err)
	}
	tag1 := registry.WrapTag(rc.lane.LaneID, "s1", rc.state.specHashes["s1"])
	tag2 := registry.WrapTag(rc.lane.LaneID, "s2", rc.state.specHashes["s2"])
	eng.saveTars = map[string][]byte{tag1: tar1, tag2: tar2}

	scratchDir := t.TempDir()
	mounts, mountErr := rc.buildInputMounts(context.Background(), rc.dag.Steps["consumer"], scratchDir)
	if mountErr != nil {
		t.Fatalf("buildInputMounts: %v", mountErr)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
}

func TestBuildInputMounts_MissingSubpath(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
			},
			{
				Name: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "src.tree", Subpath: lane.Ptr(lane.RelPath("nonexistent.json")), Mount: "/in/x"},
				},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	srcDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	if err := rc.laneState.Register("src", "tree", lane.Artifact{
		Type: "directory", Digest: srcDigest,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["src"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	// Build a test OCI tar with a "tree" directory containing only "actual.json".
	tarBytes, _, err := regtest.BuildImageTar("tree/actual.json", []byte("{}"))
	if err != nil {
		t.Fatalf("BuildImageTar: %v", err)
	}
	tag := registry.WrapTag(rc.lane.LaneID, "src", rc.state.specHashes["src"])
	eng.saveTars = map[string][]byte{tag: tarBytes}

	scratchDir := t.TempDir()
	_, mountErr := rc.buildInputMounts(context.Background(), rc.dag.Steps["consumer"], scratchDir)
	if mountErr == nil {
		t.Fatal("expected error for missing subpath")
	}
	if !strings.Contains(mountErr.Error(), "subpath") {
		t.Errorf("error should mention 'subpath': %v", mountErr)
	}
	if !strings.Contains(mountErr.Error(), "src.tree") {
		t.Errorf("error should mention producer ref 'src.tree': %v", mountErr)
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
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "publish", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "pack.img", Mount: "/in/img"}},
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
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "publish", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Peers:  []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
				Inputs: []lane.InputRef{{From: "pack.img", Mount: "/in/img"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)
	if err := rc.laneState.Register("pack", "img", lane.Artifact{
		Type: "image", Digest: lane.MustParseDigest("sha256:aabb000000000000000000000000000000000000000000000000000000000000"), Signed: true,
	}); err != nil {
		t.Fatal(err)
	}

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
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "publish", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Peers:  []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
				Inputs: []lane.InputRef{{From: "pack.img", Mount: "/in/img"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)
	if err := rc.laneState.Register("pack", "img", lane.Artifact{
		Type: "image", Digest: lane.MustParseDigest("sha256:aabb000000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

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
				Name: "compile", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
			},
			{
				Name: "run", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Peers:  []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
				Inputs: []lane.InputRef{{From: "compile.bin", Mount: "/in/bin"}},
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

	h1, tag1, err := rc.computeSpecHash(step, "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	h2, tag2, err := rc.computeSpecHash(step, "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
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

	h1, _, err := rc.computeSpecHash(step, "s", lane.MustParseDigest("sha256:aaa0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	// Reset specHashes to avoid accumulation from prior call.
	rc.state.specHashes = map[string]lane.Digest{}
	h2, _, err := rc.computeSpecHash(step, "s", lane.MustParseDigest("sha256:bbb0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("different image digests should produce different hashes")
	}
}

func TestComputeSpecHash_NoSources(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})

	step := &lane.Step{
		Args: []string{"build"},
		Env:  map[string]string{},
	}

	h, _, err := rc.computeSpecHash(step, "build", lane.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000001"))
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
	eng := &mockEngine{inspectErr: fmt.Errorf("image localhost/strike/lane/step1:abc not found")}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Name:    "step1",
		Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
	}
	rc.state.specHashes["step1"] = lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000")

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Error("expected cache miss")
	}
}

func TestCheckCache_Hit(t *testing.T) {
	digest := testFullDigest
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: digest,
			Annotations: map[string]string{
				"dev.strike.content-size": "42",
			},
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Name:    "step1",
		Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
	}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hit {
		t.Error("expected cache hit")
	}
	art, err2 := rc.laneState.Resolve("step1.bin")
	if err2 != nil {
		t.Fatalf("artifact not registered: %v", err2)
	}
	if art.Size != 42 {
		t.Errorf("size = %d, want 42", art.Size)
	}
	if art.Digest.String() != digest {
		t.Errorf("digest = %q, want %q", art.Digest, digest)
	}
}

func TestCheckCache_HitMissingSizeAnnotation(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest:      testFullDigest,
			Annotations: map[string]string{},
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{Name: "step1"}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Error("expected cache miss for missing annotation")
	}
}

func TestCheckCache_HitBadSizeAnnotation(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: testFullDigest,
			Annotations: map[string]string{
				"dev.strike.content-size": "not-a-number",
			},
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{Name: "step1"}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Error("expected cache miss for bad size annotation")
	}
}

func TestCheckCache_ForceRunBypass(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: testFullDigest,
			Annotations: map[string]string{
				"dev.strike.content-size": "42",
			},
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{Name: "step1", ForceRun: true}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Error("expected cache miss with force_run")
	}
}

func TestCheckCache_EngineError(t *testing.T) {
	eng := &mockEngine{inspectErr: fmt.Errorf("engine unavailable")}
	rc := newTestRC(t, eng)
	step := &lane.Step{Name: "step1"}

	_, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckCache_HitRestoresSignedFromAnnotation(t *testing.T) {
	digest := testFullDigest
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: digest,
			Annotations: map[string]string{
				"dev.strike.content-size": "100",
				"dev.strike.signed":       "true",
			},
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Name:    "step1",
		Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
	}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	art, err2 := rc.laneState.Resolve("step1.img")
	if err2 != nil {
		t.Fatalf("artifact not registered: %v", err2)
	}
	if !art.Signed {
		t.Error("expected Signed=true from annotation")
	}
}

func TestCheckCache_AbsentSignedAnnotationDefaultsFalse(t *testing.T) {
	digest := testFullDigest
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: digest,
			Annotations: map[string]string{
				"dev.strike.content-size": "100",
			},
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Name:    "step1",
		Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
	}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	art, err2 := rc.laneState.Resolve("step1.bin")
	if err2 != nil {
		t.Fatalf("artifact not registered: %v", err2)
	}
	if art.Signed {
		t.Error("expected Signed=false when annotation absent")
	}
}

// --------------------------------------------------------------------------.
// resolveImageDigest
// --------------------------------------------------------------------------.

func TestResolveImageDigest_FromRef(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	step := &lane.Step{Image: lane.Ptr(lane.ImageRef("docker.io/lib/golang@sha256:abcdef1234567890000000000000000000000000000000000000000000000000"))}

	digest, err := rc.resolveImageDigest(context.Background(), step, "test")
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "sha256:abcdef1234567890000000000000000000000000000000000000000000000000" {
		t.Errorf("digest = %q, want sha256:abcdef1234567890", digest.String())
	}
}

func TestResolveImageDigest_FromInspect(t *testing.T) {
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000002",
		},
	}
	rc := newTestRC(t, eng)
	step := &lane.Step{Image: lane.Ptr(lane.ImageRef("docker.io/lib/golang:1.22"))}

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
		LaneID:   "test-lane",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFrom: &lane.ImageFrom{Step: "pack", Output: "img"},
			},
		},
	}
	rc.lane = p
	rc.dag = buildTestDAG(t, p)
	if err := rc.laneState.Register("pack", "img", lane.Artifact{
		Type: "image", Digest: lane.MustParseDigest("sha256:abcdef1234567890000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}
	producerSpecHash := lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")
	rc.state.specHashes["pack"] = producerSpecHash

	step := rc.dag.Steps["run"]
	imageBefore := step.Image
	digest, err := rc.resolveImageDigest(context.Background(), step, "test")
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "sha256:abcdef1234567890000000000000000000000000000000000000000000000000" {
		t.Errorf("digest = %q, want sha256:abcdef123456789000", digest.String())
	}
	if step.Image != imageBefore {
		t.Errorf("resolveImageDigest must not mutate step.Image; got %v, was %v",
			step.Image, imageBefore)
	}
	got := rc.state.imageFromTags["run"]
	want := registry.WrapTag("test-lane", "pack", producerSpecHash)
	if got != want {
		t.Errorf("imageFromTags[run] = %q, want %q", got, want)
	}
}

func TestResolveImageDigest_ImageFromMissing(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
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
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

// --------------------------------------------------------------------------.
// resolvePackInputPaths
// --------------------------------------------------------------------------.

func TestResolvePackInputPaths(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "compile", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "compile.bin", Dest: "/app"}},
				},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	compileDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	if err := rc.laneState.Register("compile", "bin", lane.Artifact{
		Type: "file", Digest: compileDigest,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["compile"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	tarBytes, _, err := regtest.BuildImageTar("binary", []byte("bin"))
	if err != nil {
		t.Fatalf("BuildImageTar: %v", err)
	}
	tag := registry.WrapTag(rc.lane.LaneID, "compile", rc.state.specHashes["compile"])
	eng.saveTars = map[string][]byte{tag: tarBytes}

	scratchDir := t.TempDir()
	paths, pathErr := rc.resolvePackInputPaths(context.Background(), rc.dag.Steps["pack"], scratchDir, "test")
	if pathErr != nil {
		t.Fatal(pathErr)
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
	rc.lane.Secrets = map[string]lane.SecretSource{
		"cosign_key":      testCosignKeyRef,
		"cosign_password": testCosignUnlockRef,
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
		Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
	}
	if err := rc.pushAndReport(context.Background(), step, "test", "tag"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushAndReport_ImagePushError(t *testing.T) {
	eng := &mockEngine{pushErr: fmt.Errorf("network down")}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
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
		Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
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
		Timeout: lane.Ptr(lane.Duration("not-a-duration")),
		Image:   lane.Ptr(lane.ImageRef("img@sha256:abc0000000000000000000000000000000000000000000000000000000000000")),
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

func TestRunStep_TimeoutFromLaneDefaults(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	rc.lane.Defaults = &lane.LaneDefaults{Timeout: "invalid"}
	rc.dag.Steps["bad"] = &lane.Step{
		Image: lane.Ptr(lane.ImageRef("img@sha256:abc0000000000000000000000000000000000000000000000000000000000000")),
		Args:  []string{"run"},
		Env:   map[string]string{},
	}

	err := rc.runStep("bad")
	if err == nil {
		t.Fatal("expected error for invalid lane-defaults timeout")
	}
	if !strings.Contains(err.Error(), "invalid timeout") {
		t.Errorf("error should mention 'invalid timeout': %v", err)
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention the offending value: %v", err)
	}
}

// --------------------------------------------------------------------------.
// newRunState
// --------------------------------------------------------------------------.

func TestNewRunState(t *testing.T) {
	s := newRunState()
	if s.specHashes == nil {
		t.Fatal("specHashes should be initialized")
	}
}

// --------------------------------------------------------------------------.
// validateMountSymlinks
// --------------------------------------------------------------------------.

func TestValidateMountSymlinks(t *testing.T) {
	cases := []struct {
		build   func(t *testing.T, dir string) string // returns the srcPath to validate
		name    string
		wantErr bool
	}{
		{
			name: "contained sibling link",
			build: func(t *testing.T, dir string) string {
				if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantErr: false,
		},
		{
			name: "escaping relative link",
			build: func(t *testing.T, dir string) string {
				if err := os.Symlink("../escape", filepath.Join(dir, "link")); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantErr: true,
		},
		{
			name: "absolute link",
			build: func(t *testing.T, dir string) string {
				if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantErr: true,
		},
		{
			name: "subpath severs a contained link",
			build: func(t *testing.T, dir string) string {
				// Full tree: pkg/website -> ../shared/x, with shared/x present.
				// Contained in the full tree, severed when only pkg is mounted.
				if err := os.MkdirAll(filepath.Join(dir, "shared", "x"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../shared/x", filepath.Join(dir, "pkg", "website")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(dir, "pkg") // validate as the mounted subpath
			},
			wantErr: true,
		},
		{
			name: "mount source is itself a symlink",
			build: func(t *testing.T, dir string) string {
				if err := os.MkdirAll(filepath.Join(dir, "target"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", filepath.Join(dir, "linkdir")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(dir, "linkdir")
			},
			wantErr: true,
		},
		{
			name: "regular file mount",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "file.txt")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := c.build(t, t.TempDir())
			err := validateMountSymlinks(src)
			if c.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
