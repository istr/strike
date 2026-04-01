package main

import (
	"testing"

	"github.com/istr/strike/lane"
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

	// Unsigned input + network step → must be blocked
	step := dag.Steps["publish"]
	for _, inp := range step.Inputs {
		if dag.IsOCITarOutput(inp) && !ociSigned[inp.From+"/"+inp.Name] {
			// Expected: this path is taken
			return
		}
	}
	t.Fatal("expected unsigned OCI input to be blocked for network step")
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
