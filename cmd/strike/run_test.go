package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/front"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

const testAlgoSHA256 = "sha256"

const (
	testFullDigestHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	testFullDigest    = "sha256:" + testFullDigestHex
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
	ft, ftErr := front.New(context.Background())
	if ftErr != nil {
		t.Fatalf("front.New: %v", ftErr)
	}
	t.Cleanup(func() {
		if cErr := ft.Close(); cErr != nil {
			t.Logf("close front: %v", cErr)
		}
	})
	return &runContext{
		ctx:       context.Background(),
		lane:      &lane.Lane{Registry: "localhost:5555/test"},
		dag:       &lane.DAG{Steps: map[string]*lane.Step{}},
		regClient: &registry.Client{Engine: engine},
		engine:    engine,
		front:     ft,
		state:     newRunState(),
		laneState: lane.NewState(),
		laneRoot:  root,
		laneDir:   dir,
	}
}

// --------------------------------------------------------------------------.
// buildInputDelivery
// --------------------------------------------------------------------------.

func TestBuildInputDelivery_Single(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "compile", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))}},
			},
			{
				ID: "test", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Workdir: lane.Ptr(lane.AbsPath("/work")),
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "compile", Output: "bin"}, Mount: "/work/binary"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	compileDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	compileRef := "localhost/test/compile@" + compileDigest.String()
	tarBytes, diffID, err := regtest.BuildLayeredImageTar("bin", map[string][]byte{"binary": []byte("data")})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar: %v", err)
	}
	if err := rc.laneState.Register("compile", "bin", lane.OutputHandle{
		ImageRef:    compileRef,
		LayerID:     "bin",
		LayerDiffID: diffID,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["compile"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{compileRef: tarBytes}

	seeds, _, seedErr := rc.buildInputDelivery(context.Background(), rc.dag.Steps["test"])
	if seedErr != nil {
		t.Fatalf("buildInputDelivery: %v", seedErr)
	}
	if len(seeds) != 1 {
		t.Fatalf("expected 1 seed, got %d", len(seeds))
	}
	if seeds[0].Path != "/work" {
		t.Errorf("seed path = %q, want /work", seeds[0].Path)
	}
}

func TestBuildInputDelivery_Multiple(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "s1", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "a", Type: "file", Path: lane.Ptr(lane.RelPath("a.tar"))}},
			},
			{
				ID: "s2", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "b", Type: "file", Path: lane.Ptr(lane.RelPath("b.tar"))}},
			},
			{
				ID: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Workdir: lane.Ptr(lane.AbsPath("/work")),
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "s1", Output: "a"}, Mount: "/work/a"},
					{From: lane.OutputRef{Step: "s2", Output: "b"}, Mount: "/work/b"},
				},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	d1 := lane.MustParseDigest("sha256:aaaa111122223333000000000000000000000000000000000000000000000000")
	d2 := lane.MustParseDigest("sha256:bbbb444455556666000000000000000000000000000000000000000000000000")
	ref1 := "localhost/test/s1@" + d1.String()
	ref2 := "localhost/test/s2@" + d2.String()
	tar1, diff1, err := regtest.BuildLayeredImageTar("a", map[string][]byte{"a.tar": []byte("a")})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar s1: %v", err)
	}
	tar2, diff2, err := regtest.BuildLayeredImageTar("b", map[string][]byte{"b.tar": []byte("b")})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar s2: %v", err)
	}
	if err := rc.laneState.Register("s1", "a", lane.OutputHandle{ImageRef: ref1, LayerID: "a", LayerDiffID: diff1}); err != nil {
		t.Fatal(err)
	}
	if err := rc.laneState.Register("s2", "b", lane.OutputHandle{ImageRef: ref2, LayerID: "b", LayerDiffID: diff2}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["s1"] = lane.MustParseDigest("sha256:2222222222222222000000000000000000000000000000000000000000000000")
	rc.state.specHashes["s2"] = lane.MustParseDigest("sha256:3333333333333333000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{ref1: tar1, ref2: tar2}

	seeds, _, seedErr := rc.buildInputDelivery(context.Background(), rc.dag.Steps["consumer"])
	if seedErr != nil {
		t.Fatalf("buildInputDelivery: %v", seedErr)
	}
	if len(seeds) != 2 {
		t.Fatalf("expected 2 seeds, got %d", len(seeds))
	}
}

func TestBuildInputDelivery_MissingSubpath(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
			},
			{
				ID: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Workdir: lane.Ptr(lane.AbsPath("/work")),
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Subpath: lane.Ptr(lane.RelPath("nonexistent.json")), Mount: "/work/x"},
				},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	srcDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	srcRef := "localhost/test/src@" + srcDigest.String()
	tarBytes, diffID, err := regtest.BuildLayeredImageTar("tree", map[string][]byte{"tree/actual.json": []byte("{}")})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar: %v", err)
	}
	if err := rc.laneState.Register("src", "tree", lane.OutputHandle{
		ImageRef:    srcRef,
		LayerID:     "tree",
		LayerDiffID: diffID,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["src"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{srcRef: tarBytes}

	_, _, seedErr := rc.buildInputDelivery(context.Background(), rc.dag.Steps["consumer"])
	if seedErr == nil {
		t.Fatal("expected error for missing subpath")
	}
	if !strings.Contains(seedErr.Error(), "subpath") {
		t.Errorf("error should mention 'subpath': %v", seedErr)
	}
}

func TestBuildInputDelivery_OutsideWorkdir_DirectoryMount(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
			},
			{
				ID: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Workdir: lane.Ptr(lane.AbsPath("/work")),
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "src", Output: "tree"}, Mount: "/outside/tree"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	srcDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	srcRef := "localhost/test/src@" + srcDigest.String()
	tarBytes, diffID, err := regtest.BuildLayeredImageTar("tree", map[string][]byte{
		"tree/a.txt": []byte("a"),
	})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar: %v", err)
	}
	if err := rc.laneState.Register("src", "tree", lane.OutputHandle{
		ImageRef:    srcRef,
		LayerID:     "tree",
		LayerDiffID: diffID,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["src"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{srcRef: tarBytes}

	seeds, mounts, dErr := rc.buildInputDelivery(context.Background(), rc.dag.Steps["consumer"])
	if dErr != nil {
		t.Fatalf("buildInputDelivery: %v", dErr)
	}
	if len(seeds) != 0 {
		t.Errorf("expected 0 seeds, got %d", len(seeds))
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Source != srcRef {
		t.Errorf("mount Source = %q, want %q", mounts[0].Source, srcRef)
	}
	if mounts[0].Destination != "/outside/tree" {
		t.Errorf("mount Destination = %q, want /outside/tree", mounts[0].Destination)
	}
	if mounts[0].SubPath != "tree" {
		t.Errorf("mount SubPath = %q, want tree", mounts[0].SubPath)
	}
	if mounts[0].ReadWrite {
		t.Error("mount ReadWrite = true, want false")
	}
}

func TestBuildInputDelivery_NoWorkdir_Mounts(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
			},
			{
				ID: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "src", Output: "tree"}, Mount: "/in/tree"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	srcDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	srcRef := "localhost/test/src@" + srcDigest.String()
	tarBytes, diffID, err := regtest.BuildLayeredImageTar("tree", map[string][]byte{
		"tree/a.txt": []byte("a"),
	})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar: %v", err)
	}
	if err := rc.laneState.Register("src", "tree", lane.OutputHandle{
		ImageRef:    srcRef,
		LayerID:     "tree",
		LayerDiffID: diffID,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["src"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{srcRef: tarBytes}

	seeds, mounts, dErr := rc.buildInputDelivery(context.Background(), rc.dag.Steps["consumer"])
	if dErr != nil {
		t.Fatalf("buildInputDelivery: %v", dErr)
	}
	if len(seeds) != 0 {
		t.Errorf("expected 0 seeds, got %d", len(seeds))
	}
	if len(mounts) != 1 || mounts[0].Destination != "/in/tree" {
		t.Fatalf("expected 1 mount at /in/tree, got %+v", mounts)
	}
}

func TestBuildInputDelivery_SingleFileOutside_Rejected(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))}},
			},
			{
				ID: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Workdir: lane.Ptr(lane.AbsPath("/work")),
				Inputs:  []lane.InputRef{{From: lane.OutputRef{Step: "src", Output: "bin"}, Mount: "/outside/binary"}},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	if err := rc.laneState.Register("src", "bin", lane.OutputHandle{
		ImageRef: "localhost/test/src@sha256:aabbccdd11223344000000000000000000000000000000000000000000000000",
		LayerID:  "bin",
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["src"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	_, _, err := rc.buildInputDelivery(context.Background(), rc.dag.Steps["consumer"])
	if err == nil {
		t.Fatal("expected single-file-outside rejection")
	}
	if !strings.Contains(err.Error(), "single file") {
		t.Errorf("error should explain the single-file constraint in lane terms: %v", err)
	}
}

func TestBuildInputDelivery_ExportsProducerOnce(t *testing.T) {
	eng := &mockEngine{}
	rc := newTestRC(t, eng)

	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
			},
			{
				ID: "consumer", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Workdir: lane.Ptr(lane.AbsPath("/work")),
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Subpath: lane.Ptr(lane.RelPath("a.txt")), Mount: "/work/a.txt"},
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Subpath: lane.Ptr(lane.RelPath("b.txt")), Mount: "/work/b.txt"},
				},
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	srcDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	srcRef := "localhost/test/src@" + srcDigest.String()
	tarBytes, diffID, err := regtest.BuildLayeredImageTar("tree", map[string][]byte{
		"tree/a.txt": []byte("a"),
		"tree/b.txt": []byte("b"),
	})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar: %v", err)
	}
	if err := rc.laneState.Register("src", "tree", lane.OutputHandle{
		ImageRef:    srcRef,
		LayerID:     "tree",
		LayerDiffID: diffID,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["src"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{srcRef: tarBytes}

	seeds, _, seedErr := rc.buildInputDelivery(context.Background(), rc.dag.Steps["consumer"])
	if seedErr != nil {
		t.Fatalf("buildInputDelivery: %v", seedErr)
	}
	if len(seeds) != 2 {
		t.Fatalf("expected 2 seeds, got %d", len(seeds))
	}
	if got := eng.saveCalls[srcRef]; got != 1 {
		t.Errorf("SaveImage for %s called %d times, want 1 (one export per producer)", srcRef, got)
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
		ID:      "step1",
		Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
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
		ID:      "step1",
		Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
	}

	// On a cache hit, checkCache exports the cached image and recovers each
	// output's LayerDiffID from the config rootfs.diff_ids in canonical layer
	// order. Provide a one-layer image keyed by the digest ref it pulls.
	imageRef := registry.WrapDigestRef(rc.lane.ID, "step1", lane.MustParseDigest(digest))
	tarBytes, diffID, buildErr := regtest.BuildLayeredImageTar("bin", map[string][]byte{"bin": []byte("data")})
	if buildErr != nil {
		t.Fatalf("BuildLayeredImageTar: %v", buildErr)
	}
	eng.saveTars = map[string][]byte{imageRef: tarBytes}

	hit, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hit {
		t.Error("expected cache hit")
	}
	handle, err2 := rc.laneState.Resolve("step1.bin")
	if err2 != nil {
		t.Fatalf("output not registered: %v", err2)
	}
	gotDigest, digestErr := handle.ManifestDigest()
	if digestErr != nil {
		t.Fatalf("manifest digest: %v", digestErr)
	}
	if gotDigest.String() != digest {
		t.Errorf("digest = %q, want %q", gotDigest, digest)
	}
	if handle.LayerDiffID != diffID {
		t.Errorf("LayerDiffID = %q, want %q (recovered from cached image)", handle.LayerDiffID, diffID)
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
	step := &lane.Step{ID: "step1"}

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
	step := &lane.Step{ID: "step1"}

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
	step := &lane.Step{ID: "step1", ForceRun: true}

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
	step := &lane.Step{ID: "step1"}

	_, err := rc.checkCache(context.Background(), step, "step1", "step1", lane.MustParseDigest("sha256:abc0000000000000000000000000000000000000000000000000000000000000"))
	if err == nil {
		t.Fatal("expected error")
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
		ID:       "test-lane",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFromStep: "pack",
			},
		},
	}
	rc.lane = p
	rc.dag = buildTestDAG(t, p)
	packDigest := lane.MustParseDigest("sha256:abcdef1234567890000000000000000000000000000000000000000000000000")
	if err := rc.laneState.Register("pack", "", lane.OutputHandle{
		ImageRef: registry.WrapDigestRef("test-lane", "pack", packDigest),
	}); err != nil {
		t.Fatal(err)
	}
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
	got := rc.state.imageFromRefs["run"]
	want := registry.WrapDigestRef("test-lane", "pack", digest)
	if got != want {
		t.Errorf("imageFromRefs[run] = %q, want %q", got, want)
	}
}

func TestResolveImageDigest_ImageFromMissing(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Output: "image",
			},
			{
				ID: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFromStep: "pack",
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
				ID: "compile", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))}},
			},
			{
				ID: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: lane.OutputRef{Step: "compile", Output: "bin"}, Dest: "/app"}},
				},
				Output: "image",
			},
		},
	}
	rc.dag = buildTestDAG(t, p)

	compileDigest := lane.MustParseDigest("sha256:aabbccdd11223344000000000000000000000000000000000000000000000000")
	compileRef := "localhost/test/compile@" + compileDigest.String()
	tarBytes, diffID, err := regtest.BuildLayeredImageTar("bin", map[string][]byte{"binary": []byte("bin")})
	if err != nil {
		t.Fatalf("BuildLayeredImageTar: %v", err)
	}
	if err := rc.laneState.Register("compile", "bin", lane.OutputHandle{
		ImageRef:    compileRef,
		LayerID:     "bin",
		LayerDiffID: diffID,
	}); err != nil {
		t.Fatal(err)
	}
	rc.state.specHashes["compile"] = lane.MustParseDigest("sha256:1111111111111111000000000000000000000000000000000000000000000000")

	eng.saveTars = map[string][]byte{compileRef: tarBytes}

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
// pushAndReport
// --------------------------------------------------------------------------.

func TestPushAndReport_NoImage(t *testing.T) {
	rc := newTestRC(t, &mockEngine{})
	step := &lane.Step{
		Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
	}
	if err := rc.pushAndReport(context.Background(), step, "test", "tag"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushAndReport_ImagePushError(t *testing.T) {
	eng := &mockEngine{pushErr: fmt.Errorf("network down")}
	rc := newTestRC(t, eng)
	step := &lane.Step{
		Output: "image",
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
		Output: "image",
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
// archiveReroot
// --------------------------------------------------------------------------.

func TestArchiveReroot(t *testing.T) {
	tests := []struct {
		name                             string
		workdir                          string
		out                              lane.FileOutput
		wantArchive, wantStrip, wantDest string
	}{
		{
			name:        "directory with path",
			workdir:     "/out",
			out:         lane.FileOutput{ID: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))},
			wantArchive: "/out/tree", wantStrip: "tree", wantDest: "tree",
		},
		{
			name:        "directory nested path",
			workdir:     "/out",
			out:         lane.FileOutput{ID: "web", Type: "directory", Path: lane.Ptr(lane.RelPath("dist/web"))},
			wantArchive: "/out/dist/web", wantStrip: "web", wantDest: "web",
		},
		{
			name:        "directory whole workdir (no path)",
			workdir:     "/out",
			out:         lane.FileOutput{ID: "site", Type: "directory"},
			wantArchive: "/out", wantStrip: "", wantDest: "site",
		},
		{
			name:        "file with path",
			workdir:     "/out",
			out:         lane.FileOutput{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))},
			wantArchive: "/out/binary", wantStrip: "", wantDest: "",
		},
		{
			name:        "file nested path",
			workdir:     "/out",
			out:         lane.FileOutput{ID: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("build/app.bin"))},
			wantArchive: "/out/build/app.bin", wantStrip: "", wantDest: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, s, d := archiveReroot(tt.workdir, tt.out)
			if a != tt.wantArchive || s != tt.wantStrip || d != tt.wantDest {
				t.Errorf("archiveReroot = (%q, %q, %q), want (%q, %q, %q)",
					a, s, d, tt.wantArchive, tt.wantStrip, tt.wantDest)
			}
		})
	}
}
