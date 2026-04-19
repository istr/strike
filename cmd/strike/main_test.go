package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

func TestUnsignedOCIInputBlocksNetworkStep(t *testing.T) {
	// Simulate the check logic from cmdRun: a network-enabled step
	// with an unsigned oci-tar input must be rejected.
	dag := &lane.DAG{
		Steps: map[string]*lane.Step{
			"pack_unsigned": {
				Name: "pack_unsigned",
				Outputs: []lane.OutputSpec{
					{Name: "image", Type: "image", Path: "/out/image.tar"},
				},
			},
			"pack_signed": {
				Name: "pack_signed",
				Outputs: []lane.OutputSpec{
					{Name: "image", Type: "image", Path: "/out/image.tar"},
				},
			},
			"publish": {
				Name:    "publish",
				Network: true,
				Inputs: []lane.InputRef{
					{Name: "image", From: "pack_unsigned", Mount: "/run/image.tar"},
				},
			},
			"publish_signed": {
				Name:    "publish_signed",
				Network: true,
				Inputs: []lane.InputRef{
					{Name: "image", From: "pack_signed", Mount: "/run/image.tar"},
				},
			},
		},
	}

	ociSigned := map[string]bool{
		"pack_unsigned/image": false,
		"pack_signed/image":   true,
	}

	// Unsigned input + network step -> must be blocked
	step := dag.Steps["publish"]
	for _, inp := range step.Inputs {
		if dag.IsOCITarOutput(inp) && !ociSigned[inp.From+"/"+inp.Name] {
			// Expected: this path is taken
			return
		}
	}
	t.Fatal("expected unsigned OCI input to be blocked for network step")
}

func TestHashConsistency(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src", "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "a.go"), []byte("package a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "sub", "b.go"), []byte("package b"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // test cleanup

	h1, err := registry.HashPath(root, dir, "src")
	if err != nil {
		t.Fatalf("registry.HashPath: %v", err)
	}
	h2, err := lane.SourceDigest(root, dir, "src")
	if err != nil {
		t.Fatalf("lane.SourceDigest: %v", err)
	}

	// Both functions return typed digests in "sha256:<hex>" format.
	if h1 != h2 {
		t.Fatalf("hash mismatch:\n  registry.HashPath:  %s\n  lane.SourceDigest: %s", h1, h2)
	}
}

func TestSignedOCIInputAllowsNetworkStep(t *testing.T) {
	dag := &lane.DAG{
		Steps: map[string]*lane.Step{
			"pack_signed": {
				Name: "pack_signed",
				Outputs: []lane.OutputSpec{
					{Name: "image", Type: "image", Path: "/out/image.tar"},
				},
			},
			"publish": {
				Name:    "publish",
				Network: true,
				Inputs: []lane.InputRef{
					{Name: "image", From: "pack_signed", Mount: "/run/image.tar"},
				},
			},
		},
	}

	ociSigned := map[string]bool{
		"pack_signed/image": true,
	}

	step := dag.Steps["publish"]
	for _, inp := range step.Inputs {
		if dag.IsOCITarOutput(inp) && !ociSigned[inp.From+"/"+inp.Name] {
			t.Fatalf("signed OCI input %s/%s should not be blocked", inp.From, inp.Name)
		}
	}
}
