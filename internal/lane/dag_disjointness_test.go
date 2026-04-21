package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// twoInputLane builds a lane where step "c" mounts outputs from "a" and "b"
// at the given container paths.
func twoInputLane(mountA, mountB lane.ContainerPath) *lane.Lane {
	return &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "a", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "o", Type: "file", Path: "/out/o"}},
			},
			{
				Name: "b", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "o", Type: "file", Path: "/out/o"}},
			},
			{
				Name: "c", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{Name: "x", From: "a.o", Mount: mountA},
					{Name: "y", From: "b.o", Mount: mountB},
				},
			},
		},
	}
}

func TestBuild_NestedInputMountsRejected(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				Name: "src", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{
					{Name: "tree", Type: "directory", Path: "/out/tree"},
				},
			},
			{
				Name: "deps", Image: "img", Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{
					{Name: "node_modules", Type: "directory", Path: "/out/node_modules"},
				},
			},
			{
				Name: "build", Image: "img", Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{Name: "tree", From: "src.tree", Mount: "/work"},
					{Name: "deps", From: "deps.node_modules", Mount: "/work/node_modules"},
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
	// "/work" must not match "/workspace" — only path-component prefixes count
	if _, err := lane.Build(twoInputLane("/work", "/workspace")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
