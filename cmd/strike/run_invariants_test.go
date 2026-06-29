package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// --------------------------------------------------------------------------.
// Negative: structural invariants enforced by Build.
// --------------------------------------------------------------------------.

func TestBuild_RejectsNestedInputMounts(t *testing.T) {
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID: "src", Image: primitive.ImageRefPtr("img@sha256:" + strings.Repeat("a", 64)),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: primitive.RelPathPtr("tree")}},
			},
			{
				ID: "deps", Image: primitive.ImageRefPtr("img@sha256:" + strings.Repeat("b", 64)),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "modules", Type: "directory", Path: primitive.RelPathPtr("modules")}},
			},
			{
				ID: "build", Image: primitive.ImageRefPtr("img@sha256:" + strings.Repeat("c", 64)),
				Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{From: lane.OutputRef{Step: "src", Output: "tree"}, Mount: "/work"},
					{From: lane.OutputRef{Step: "deps", Output: "modules"}, Mount: "/work/node_modules"},
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error: nested input mounts must be rejected")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Errorf("error should mention 'overlap': %v", err)
	}
}

func TestBuild_RejectsProvenancePathOutsideOutputs(t *testing.T) {
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "src", Image: primitive.ImageRefPtr("img@sha256:" + strings.Repeat("a", 64)),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "tree", Type: "directory", Path: primitive.RelPathPtr("tree")}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "../escape.json",
				},
			},
		},
	}
	_, err := lane.Build(p)
	if err == nil {
		t.Fatal("expected error: provenance path outside outputs")
	}
}

func TestParse_RejectsSourcesField(t *testing.T) {
	yaml := `
name: bad
registry: localhost:5555/test
secrets: {}
resolver:
  host: "1.1.1.1:853"
  trust:
    type: certFingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - id: build
    image: img@sha256:` + strings.Repeat("a", 64) + `
    args: []
    env: {}
    inputs: []
    sources:
      - { path: ".", mount: /src }
    outputs:
      - id: bin
        type: file
        path: /out/bin
`
	tmpFile := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(tmpFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	fp, fpErr := lane.NewFilePath(tmpFile)
	if fpErr != nil {
		t.Fatalf("NewFilePath: %v", fpErr)
	}
	_, _, err := lane.Parse(fp)
	if err == nil {
		t.Fatal("expected parse error: 'sources' field does not exist in schema")
	}
}

// --------------------------------------------------------------------------.
// Provenance capture: validate + record + collect through lane state.
// --------------------------------------------------------------------------.

func TestProvenanceCapture_EndToEnd(t *testing.T) {
	fp, fpErr := lane.NewFilePath("testdata/hugo.yaml")
	if fpErr != nil {
		t.Fatal(fpErr)
	}
	p, _, err := lane.Parse(fp)
	if err != nil {
		t.Fatal(err)
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}

	state := lane.NewState()

	// Simulate provenance capture for steps that declare provenance.
	// This exercises ValidateProvenance -> RecordProvenance -> CollectProvenance.
	for _, stepID := range dag.Order {
		step := dag.Steps[stepID]
		if step.Provenance == nil {
			continue
		}
		raw := fakeProvenanceJSON(t, step.Provenance.Type)
		rec, err := lane.ValidateProvenance(step.Provenance.Type, raw)
		if err != nil {
			t.Fatalf("ValidateProvenance(%s): %v", stepID, err)
		}
		if err := state.RecordProvenance(stepID, rec); err != nil {
			t.Fatalf("RecordProvenance(%s): %v", stepID, err)
		}
	}

	// deploy traverses the full DAG: deploy -> pack-site -> build -> workspace -> {source, npm-install}.
	// source has provenance; CollectProvenance from deploy should find it.
	records := state.CollectProvenance(dag, "deploy")
	if len(records) == 0 {
		t.Fatal("expected at least one provenance record from upstream source step")
	}
	if records[0].ProvenanceType() != "git" {
		t.Errorf("expected git provenance, got %q", records[0].ProvenanceType())
	}
}

func fakeProvenanceJSON(t *testing.T, typ string) []byte {
	t.Helper()
	switch typ {
	case "git":
		return []byte(`{"type":"git","uri":"https://example.com/repo.git","commit":"0123456789abcdef0123456789abcdef01234567"}`)
	case "tarball":
		return []byte(`{"type":"tarball","uri":"https://example.com/x.tar","sha256":"` + strings.Repeat("a", 64) + `"}`)
	case "oci":
		return []byte(`{"type":"oci","uri":"reg/repo","digest":"sha256:` + strings.Repeat("a", 64) + `"}`)
	case "url":
		return []byte(`{"type":"url","uri":"https://example.com/x","sha256":"` + strings.Repeat("a", 64) + `"}`)
	default:
		t.Fatalf("unknown provenance type %q", typ)
		return nil
	}
}
