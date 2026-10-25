package main

import (
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

// TestRunStep_CacheHitMaterializesNothing pins that a step restored from the
// cache never consults or loads the engine store for its image: the cache
// check returns before the executor runs.
func TestRunStep_CacheHitMaterializesNothing(t *testing.T) {
	var digest primitive.Digest = testFullDigest
	eng := &mockEngine{
		inspectRV: &container.ImageInfo{
			Digest:      digest,
			Annotations: map[string]string{"dev.strike.content-size": "42"},
		},
	}
	rc := newTestRC(t, eng)
	rc.runtime = runtimeForSteps(t, "step1")
	step := &lane.Step{
		ID:      "step1",
		Image:   primitive.ImageRefPtr("docker.io/library/alpine@sha256:abababababababababababababababababababababababababababababababab"),
		Args:    []string{"true"},
		Env:     map[string]string{},
		Outputs: []lane.FileOutput{{ID: "bin", Type: "file", Path: primitive.RelPathPtr("bin")}},
	}
	rc.stepIndex["step1"] = step
	tarBytes, _, buildErr := regtest.BuildLayeredImageTar("bin", map[string][]byte{"bin": []byte("data")})
	if buildErr != nil {
		t.Fatalf("BuildLayeredImageTar: %v", buildErr)
	}
	eng.saveTars = map[string][]byte{registry.WrapDigest(rc.lane.ID, "step1", digest): tarBytes}

	if err := rc.runStep("step1"); err != nil {
		t.Fatalf("runStep: %v", err)
	}
	if eng.existsCalls != 0 || eng.loadCalls != 0 {
		t.Errorf("exists calls = %d, load calls = %d, want none on a cache hit", eng.existsCalls, eng.loadCalls)
	}
}
