// This file tests the invariant "Build-accepts ⇒ runStep is panic-free"
// using a MockEngine. It does not require Podman or network access and
// runs in the default go test invocation. Real container execution is
// covered separately by integration tests gated on STRIKE_INTEGRATION.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

func TestRunStep_RealLanePatterns_NoPanic(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yaml" {
			fixtures = append(fixtures, filepath.Join("testdata", e.Name()))
		}
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found in testdata/")
	}

	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			assertLanePanicFree(t, path)
		})
	}
}

// assertLanePanicFree parses and builds a lane, then runs every step
// through a mock engine. Errors are acceptable; panics are not.
func assertLanePanicFree(t *testing.T, path string) {
	t.Helper()
	p, err := lane.Parse(path)
	if err != nil {
		t.Fatalf("lane.Parse(%s): %v", path, err)
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatalf("lane.Build(%s): %v", path, err)
	}

	eng := &mockEngine{
		imageExistsRV: true,
		runExitCode:   0,
		inspectRV: &container.ImageInfo{
			Annotations: map[string]string{},
		},
	}
	rc := newTestRC(t, eng)
	rc.lane = p
	rc.dag = dag

	for _, stepName := range dag.Order {
		rc.state.outputDirs[stepName] = t.TempDir()
		step := dag.Steps[stepName]
		if step.Provenance != nil {
			placeFakeProvenance(t, rc.state.outputDirs[stepName], step)
		}
		if err := rc.runStep(stepName); err != nil {
			t.Logf("step %q returned error (OK, panic would not be): %v",
				stepName, err)
		}
	}
}
