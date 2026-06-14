package lane_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
)

// --------------------------------------------------------------------------.
// TestBuild -- success cases.
// --------------------------------------------------------------------------.

func TestBuild_SingleStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{Name: "build", Image: lane.Ptr(lane.ImageRef("golang")), Args: []string{"go", "build"}, Env: map[string]string{}},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(dag.Order) != 1 || dag.Order[0] != "build" {
		t.Errorf("order = %v, want [build]", dag.Order)
	}
}

func TestBuild_LinearChain(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "b", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"b"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("b"))}},
			},
			{
				Name: "c", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"c"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "b.out", Mount: "/in"}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "a", "b")
	assertOrder(t, dag.Order, "b", "c")
}

func TestBuild_Diamond(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "b", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"b"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("b"))}},
			},
			{
				Name: "c", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"c"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("c"))}},
			},
			{
				Name: "d", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"d"}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "b.out", Mount: "/in/b"},
					{From: "c.out", Mount: "/in/c"},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if dag.Order[0] != "a" {
		t.Errorf("first should be 'a', got %q", dag.Order[0])
	}
	assertOrder(t, dag.Order, "a", "b")
	assertOrder(t, dag.Order, "a", "c")
	assertOrder(t, dag.Order, "b", "d")
	assertOrder(t, dag.Order, "c", "d")
}

func TestBuild_FanOut(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "b", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"b"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "a.out", Mount: "/in"}},
			},
			{
				Name: "c", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"c"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "a.out", Mount: "/in"}},
			},
			{
				Name: "d", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"d"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "a.out", Mount: "/in"}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if dag.Order[0] != "a" {
		t.Errorf("first should be 'a', got %q", dag.Order[0])
	}
	if len(dag.Order) != 4 {
		t.Errorf("order length = %d, want 4", len(dag.Order))
	}
}

func TestBuild_ImageFromEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"pack"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{"run"},
				ImageFrom: &lane.ImageFrom{Step: "pack", Output: "img"},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "pack", "run")
}

func TestBuild_PackFileEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"build"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "binary", Type: "file", Path: lane.Ptr(lane.RelPath("binary"))}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "build.binary", Dest: "/app", Mode: 0o755}},
				},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "build", "pack")
}

func TestBuild_DeployArtifactEdge(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: "pack.img"}},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	assertOrder(t, dag.Order, "pack", "deploy")
}

// --------------------------------------------------------------------------.
// TestBuild -- error cases.
// --------------------------------------------------------------------------.

func TestBuild_DuplicateStepName(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{}},
			{Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{}},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "duplicate step name")
}

func TestBuild_UnknownImageFromStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "missing", Output: "img"},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_ImageFromWrongOutputType(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "bin", Type: "file", Path: lane.Ptr(lane.RelPath("bin"))}},
			},
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "build", Output: "bin"},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not image")
}

func TestBuild_ImageFromMissingOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{}},
			{
				Name: "run", Env: map[string]string{}, Args: []string{},
				ImageFrom: &lane.ImageFrom{Step: "build", Output: "missing"},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not found")
}

func TestBuild_UnknownInputStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "run", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "missing.out", Mount: "/in"}},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_InvalidInputRef(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "run", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "noperiod", Mount: "/in"}},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "invalid reference")
}

func TestBuild_UnknownPackFileStep(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "missing.bin", Dest: "/app"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_PackFileMissingOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "other", Type: "file", Path: lane.Ptr(lane.RelPath("other"))}},
			},
			{
				Name: "pack", Env: map[string]string{}, Args: []string{},
				Pack: &lane.PackSpec{
					Base:  "scratch",
					Files: []lane.PackFile{{From: "build.missing", Dest: "/app"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not found")
}

func TestBuild_UnknownDeployArtifact(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"img": {From: "missing.out"}},
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "unknown step")
}

func TestBuild_Cycle(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "b.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "b", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "a.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("b"))}},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "cyclic dependency")
}

// --------------------------------------------------------------------------.
// TestTree.
// --------------------------------------------------------------------------.

func TestTree(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "b", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "a.out", Mount: "/in"}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	tree := dag.Tree()
	if !strings.Contains(tree, "a") || !strings.Contains(tree, "b") {
		t.Errorf("tree should contain 'a' and 'b', got:\n%s", tree)
	}
}

// --------------------------------------------------------------------------.
// helpers.
// --------------------------------------------------------------------------.

// assertOrder verifies that 'before' appears before 'after' in the order slice.
func assertOrder(t *testing.T, order []string, before, after string) {
	t.Helper()
	bi, ai := -1, -1
	for i, s := range order {
		if s == before {
			bi = i
		}
		if s == after {
			ai = i
		}
	}
	if bi == -1 {
		t.Fatalf("%q not found in order %v", before, order)
	}
	if ai == -1 {
		t.Fatalf("%q not found in order %v", after, order)
	}
	if bi >= ai {
		t.Errorf("%q (idx %d) should come before %q (idx %d) in %v", before, bi, after, ai, order)
	}
}

// --------------------------------------------------------------------------.
// Provenance path validation.
// --------------------------------------------------------------------------.

func TestBuild_ProvenancePathInOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "tree/provenance.json",
				},
			},
		},
	}
	if _, err := lane.Build(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_ProvenancePathOutsideOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "../escape.json",
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "path traversal")
}

func TestBuild_ProvenancePathNotInOutput(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "other/provenance.json",
				},
			},
		},
	}
	_, err := lane.Build(p)
	assertErrContains(t, err, "not within any declared output")
}

// --------------------------------------------------------------------------.
// Deterministic order.
// --------------------------------------------------------------------------.

// TestBuild_DeterministicOrder asserts that lane.Build
// produces a byte-identical dag.Order across many invocations
// of the same input. With three independent root steps and
// Go's non-deterministic map iteration, a naive Kahn
// implementation would produce different orderings on
// different runs.
func TestBuild_DeterministicOrder(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "zebra", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"z"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("z"))}},
			},
			{
				Name: "alpha", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "middle", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"m"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("m"))}},
			},
		},
	}

	want := []string{"alpha", "middle", "zebra"}
	for i := range 100 {
		dag, err := lane.Build(p)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if !reflect.DeepEqual(dag.Order, want) {
			t.Fatalf("iteration %d: Order = %v, want %v "+
				"(alphabetic among independent roots)",
				i, dag.Order, want)
		}
	}
}

// TestBuild_DeterministicOrder_Diamond asserts the property
// holds for a non-trivial graph where multiple valid
// topological orderings exist: root -> {left, right} -> bottom.
func TestBuild_DeterministicOrder_Diamond(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "root", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"r"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("r"))}},
			},
			{
				Name: "right", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"rt"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "root.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("rt"))}},
			},
			{
				Name: "left", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"l"}, Env: map[string]string{},
				Inputs:  []lane.InputRef{{From: "root.out", Mount: "/in"}},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("l"))}},
			},
			{
				Name: "bottom", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"b"}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "left.out", Mount: "/in/l"},
					{From: "right.out", Mount: "/in/r"},
				},
			},
		},
	}

	// root first; left before right (alphabetic); bottom last.
	want := []string{"root", "left", "right", "bottom"}
	for i := range 100 {
		dag, err := lane.Build(p)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if !reflect.DeepEqual(dag.Order, want) {
			t.Fatalf("iteration %d: Order = %v, want %v", i, dag.Order, want)
		}
	}
}

// TestBuild_DeterministicOrder_LexSmallestNotFIFO pins the
// specific algorithmic contract: strike's kahnSort produces
// the lexicographically smallest valid topological order, not
// merely some deterministic order.
//
// On the graph below, two deterministic algorithms could
// legitimately produce different orders:
//
//   - "FIFO Kahn with sorted-at-insertion dependents":
//     [A, B, P, R, Q, S]. After processing A, P and R enter
//     the queue; after processing B, Q and S enter. The FIFO
//     does not interleave the two waves.
//   - "Lex-smallest Kahn (ready set sorted at extraction)":
//     [A, B, P, Q, R, S]. After both roots are processed, the
//     ready set is {P, Q, R, S}; the next extraction picks P
//     because it sorts first overall.
//
// Strike commits to the second behaviour for cross-
// implementation clarity. A future refactor that silently
// switches to FIFO semantics would fail this test, surfacing
// the spec drift before it could leak into attestation.
func TestBuild_DeterministicOrder_LexSmallestNotFIFO(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "A", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"a"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))}},
			},
			{
				Name: "B", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"b"}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("b"))}},
			},
			{
				Name: "P", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"p"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "A.out", Mount: "/in"}},
			},
			{
				Name: "R", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"r"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "A.out", Mount: "/in"}},
			},
			{
				Name: "Q", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"q"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "B.out", Mount: "/in"}},
			},
			{
				Name: "S", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{"s"}, Env: map[string]string{},
				Inputs: []lane.InputRef{{From: "B.out", Mount: "/in"}},
			},
		},
	}

	want := []string{"A", "B", "P", "Q", "R", "S"}
	for i := range 100 {
		dag, err := lane.Build(p)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if !reflect.DeepEqual(dag.Order, want) {
			t.Fatalf("iteration %d: Order = %v, want %v "+
				"(lex-smallest valid topology, not FIFO Kahn -- "+
				"see test doc comment for the algorithmic contract)",
				i, dag.Order, want)
		}
	}
}

// --------------------------------------------------------------------------.
// Peer anchor conflict (instruction 74).
// --------------------------------------------------------------------------.

// TestBuild_PeerAnchorConflict covers the build-time duplicate-anchor rule
// (instruction 74): same host:port with differing trust anchors is rejected;
// same anchor (including SSH known_hosts in a different order) is accepted.
func TestBuild_PeerAnchorConflict(t *testing.T) {
	// A producer step whose output the deploy step can reference,
	// so that Build succeeds past edge resolution.
	producerStep := lane.Step{
		Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{"x"}, Env: map[string]string{},
		Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
	}
	deployStep := lane.Step{
		Name: "deploy", Env: map[string]string{}, Args: []string{},
		Deploy: &lane.DeploySpec{
			Artifacts: map[string]lane.ArtifactRef{"image": {From: "pack.img"}},
		},
	}

	fpA := transport.FingerprintTrust{Type: "certFingerprint", Fingerprint: "sha256:" + strings.Repeat("a", 64)}
	fpB := transport.FingerprintTrust{Type: "certFingerprint", Fingerprint: "sha256:" + strings.Repeat("b", 64)}

	httpsStep := func(name, host string, tr transport.TLSTrust) lane.Step {
		return lane.Step{
			Name: name, Image: lane.Ptr(lane.ImageRef("img@sha256:" + strings.Repeat("a", 64))),
			Args: []string{"x"}, Env: map[string]string{},
			Peers: []lane.Peer{lane.HTTPSPeer{Type: "https", Host: transport.Host(host), Trust: tr}},
		}
	}
	sshStep := func(name, host string, kh []lane.KnownHostEntry) lane.Step {
		return lane.Step{
			Name: name, Image: lane.Ptr(lane.ImageRef("img@sha256:" + strings.Repeat("a", 64))),
			Args: []string{"x"}, Env: map[string]string{},
			Peers: []lane.Peer{lane.SSHPeer{Type: "ssh", Host: transport.Host(host), KnownHosts: kh}},
		}
	}

	khAB := []lane.KnownHostEntry{
		{KeyType: "ssh-ed25519", Key: "AAAA"},
		{KeyType: "rsa-sha2-256", Key: "BBBB"},
	}
	khBA := []lane.KnownHostEntry{
		{KeyType: "rsa-sha2-256", Key: "BBBB"},
		{KeyType: "ssh-ed25519", Key: "AAAA"},
	}

	tests := []struct {
		name    string
		steps   []lane.Step
		wantErr bool
	}{
		{
			name:    "same endpoint same fingerprint -- ok",
			steps:   []lane.Step{httpsStep("a", "h.example:443", fpA), httpsStep("b", "h.example:443", fpA), producerStep, deployStep},
			wantErr: false,
		},
		{
			name:    "same endpoint different fingerprint -- conflict",
			steps:   []lane.Step{httpsStep("a", "h.example:443", fpA), httpsStep("b", "h.example:443", fpB), producerStep, deployStep},
			wantErr: true,
		},
		{
			name:    "different endpoints -- ok",
			steps:   []lane.Step{httpsStep("a", "h.example:443", fpA), httpsStep("b", "other.example:443", fpB), producerStep, deployStep},
			wantErr: false,
		},
		{
			name:    "same endpoint https vs ssh -- conflict (C-1)",
			steps:   []lane.Step{httpsStep("a", "h.example:443", fpA), sshStep("b", "h.example:443", khAB), producerStep, deployStep},
			wantErr: true,
		},
		{
			name:    "ssh known_hosts reordered -- ok (C-2)",
			steps:   []lane.Step{sshStep("a", "h.example:22", khAB), sshStep("b", "h.example:22", khBA), producerStep, deployStep},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lane.Build(&lane.Lane{Steps: tc.steps})
			if tc.wantErr && err == nil {
				t.Fatal("expected a peer-anchor conflict error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestTree_DeduplicatesRepeatedDependency asserts that a step which
// references one producer through several inputs depends on it once:
// the dependency-graph annotation must not list the producer twice.
func TestTree_DeduplicatesRepeatedDependency(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "producer", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "directory", Path: lane.Ptr(lane.RelPath("o"))}},
			},
			{
				Name: "consumer", Image: lane.Ptr(lane.ImageRef("img")),
				Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "producer.out", Subpath: lane.Ptr(lane.RelPath("a")), Mount: "/a"},
					{From: "producer.out", Subpath: lane.Ptr(lane.RelPath("b")), Mount: "/b"},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	tree := dag.Tree()
	// consumer depends on producer exactly once, so producer appears as a
	// single child with no back-reference. A non-deduplicated edge would
	// print producer twice (one full occurrence, one "(*)").
	if got := strings.Count(tree, "producer"); got != 1 {
		t.Errorf("producer printed %d times, want 1 (edge not deduplicated?); got:\n%s", got, tree)
	}
	if got := strings.Count(tree, "consumer"); got != 1 {
		t.Errorf("consumer printed %d times, want 1; got:\n%s", got, tree)
	}
}

// TestTree_DiamondRendersSharedNodeOnce asserts that a node reachable
// through two paths is printed in full once and as a back-reference
// "(*)" once, never as two full subtrees.
func TestTree_DiamondRendersSharedNodeOnce(t *testing.T) {
	dir := func(name string, inputs ...lane.InputRef) lane.Step {
		return lane.Step{
			Name: name, Image: lane.Ptr(lane.ImageRef("img")),
			Args: []string{}, Env: map[string]string{}, Inputs: inputs,
			Outputs: []lane.OutputSpec{{Name: "out", Type: "directory", Path: lane.Ptr(lane.RelPath("o"))}},
		}
	}
	p := &lane.Lane{
		Steps: []lane.Step{
			dir("root"),
			dir("left", lane.InputRef{From: "root.out", Mount: "/r"}),
			dir("right", lane.InputRef{From: "root.out", Mount: "/r"}),
			dir("bottom",
				lane.InputRef{From: "left.out", Mount: "/l"},
				lane.InputRef{From: "right.out", Mount: "/ri"}),
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	tree := dag.Tree()
	// Rooted at the sink (bottom). root is depended on by both left and
	// right, so it is printed in full once and as a back-reference once;
	// bottom is the sole root and appears exactly once.
	if got := strings.Count(tree, "bottom"); got != 1 {
		t.Errorf("bottom (the sink/root) appears %d times, want 1; got:\n%s", got, tree)
	}
	if got := strings.Count(tree, "root"); got != 2 {
		t.Errorf("root appears %d times, want 2 (one full, one back-ref); got:\n%s", got, tree)
	}
	if got := strings.Count(tree, "(*)"); got != 1 {
		t.Errorf("expected exactly one back-reference marker, got %d; tree:\n%s", got, tree)
	}
}

// assertErrContains checks that err is non-nil and contains substr.
func assertErrContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Errorf("error %q should contain %q", err.Error(), substr)
	}
}

// --------------------------------------------------------------------------.
// ValidateLeavesAreDeploys (ADR-039 D5).
// --------------------------------------------------------------------------.

// TestValidateLeavesAreDeploys_Valid: pack is consumed by deploy, so the
// only leaf is the deploy step -- the policy passes.
func TestValidateLeavesAreDeploys_Valid(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: "pack.img"}},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := dag.ValidateLeavesAreDeploys(p); err != nil {
		t.Errorf("expected valid lane to pass, got: %v", err)
	}
}

// TestValidateLeavesAreDeploys_DeployOnly: a single deploy step is itself
// the only leaf and is a deploy -- the policy passes.
func TestValidateLeavesAreDeploys_DeployOnly(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{Artifacts: map[string]lane.ArtifactRef{}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := dag.ValidateLeavesAreDeploys(p); err != nil {
		t.Errorf("expected deploy-only lane to pass, got: %v", err)
	}
}

// TestValidateLeavesAreDeploys_DanglingLeafRejected: "orphan" produces an
// output nothing consumes and is not a deploy, so it is a non-deploy leaf.
// Build accepts the lane (the policy is the separate gate); the policy
// rejects it, naming the offending step.
func TestValidateLeavesAreDeploys_DanglingLeafRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "pack", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "img", Type: "image", Path: lane.Ptr(lane.RelPath("img.tar"))}},
			},
			{
				Name: "deploy", Env: map[string]string{}, Args: []string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: "pack.img"}},
				},
			},
			{
				Name: "orphan", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("out"))}},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatalf("Build should accept the lane (policy is separate): %v", err)
	}
	assertErrContains(t, dag.ValidateLeavesAreDeploys(p), "orphan")
}
