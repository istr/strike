package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// twoInputLane builds a lane where step "c" mounts outputs from "a" and "b"
// at the given container paths.
func twoInputLane(mountA, mountB lane.AbsPath) *lane.Lane {
	return &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "o", Type: "file", Path: lane.Ptr(lane.RelPath("o"))}},
			},
			{
				Name: "b", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "o", Type: "file", Path: lane.Ptr(lane.RelPath("o"))}},
			},
			{
				Name: "c", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "a.o", Mount: mountA},
					{From: "b.o", Mount: mountB},
				},
			},
		},
	}
}

func TestBuild_NestedInputMountsRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{
					{Name: "tree", Type: "directory", Path: lane.Ptr(lane.RelPath("tree"))},
				},
			},
			{
				Name: "deps", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{
					{Name: "node_modules", Type: "directory", Path: lane.Ptr(lane.RelPath("node_modules"))},
				},
			},
			{
				Name: "build", Image: lane.Ptr(lane.ImageRef("img")), Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: "src.tree", Mount: "/work"},
					{From: "deps.node_modules", Mount: "/work/node_modules"},
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
