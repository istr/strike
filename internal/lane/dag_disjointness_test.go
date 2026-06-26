package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/spec"
)

// twoInputLane builds a lane where step "c" mounts outputs from "a" and "b"
// at the given container paths.
func twoInputLane(mountA, mountB spec.AbsPath) *lane.Lane {
	return &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "a", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "o", Type: "file", Path: lane.Ptr(spec.RelPath("o"))}},
			},
			{
				ID: "b", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "o", Type: "file", Path: lane.Ptr(spec.RelPath("o"))}},
			},
			{
				ID: "c", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "a", Output: "o"}, Mount: mountA},
					{From: lane.OutputRef{Step: "b", Output: "o"}, Mount: mountB},
				},
			},
		},
	}
}

func TestBuild_NestedInputMountsRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "src", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{
					{ID: "tree", Type: "directory", Path: lane.Ptr(spec.RelPath("tree"))},
				},
			},
			{
				ID: "deps", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{
					{ID: "node_modules", Type: "directory", Path: lane.Ptr(spec.RelPath("node_modules"))},
				},
			},
			{
				ID: "build", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Mount: "/work"},
					{From: lane.OutputRef{Step: "deps", Output: "node_modules"}, Mount: "/work/node_modules"},
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error for nested input mounts")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Errorf("error should mention 'overlap': %v", err)
	}
}

func TestBuild_IdenticalInputMountsRejected(t *testing.T) {
	_, err := lane.Build(twoInputLane("/in", "/in"))
	if err == nil {
		t.Fatal("expected error for identical input mounts")
	}
}

func TestBuild_SiblingInputMountsAccepted(t *testing.T) {
	if _, err := lane.Build(twoInputLane("/in/x", "/in/y")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_PathPrefixNotComponentPrefix(t *testing.T) {
	// "/work" must not match "/workspace" -- only path-component prefixes count
	if _, err := lane.Build(twoInputLane("/work", "/workspace")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_DuplicateOutputIDRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "build", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{
					{ID: "bin", Type: "file", Path: lane.Ptr(spec.RelPath("one"))},
					{ID: "bin", Type: "file", Path: lane.Ptr(spec.RelPath("two"))},
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error for duplicate output id")
	}
	if !strings.Contains(err.Error(), "duplicate output id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_DistinctOutputIDsSharedBasenameAccepted(t *testing.T) {
	// Distinct ids may share a path basename -- only ids must be disjoint.
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "build", Image: lane.Ptr(spec.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{
					{ID: "first", Type: "file", Path: lane.Ptr(spec.RelPath("bin"))},
					{ID: "second", Type: "file", Path: lane.Ptr(spec.RelPath("bin"))},
				},
			},
		},
	}
	if _, err := lane.Build(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
