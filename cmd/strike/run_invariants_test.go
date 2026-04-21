package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// placeFakeProvenance writes a minimal valid provenance record for the
// step's declared type into the output directory.
func placeFakeProvenance(t *testing.T, outDir string, step *lane.Step) {
	t.Helper()
	raw := fakeProvenanceJSON(t, step.Provenance.Type)
	rel, err := filepath.Rel(outputMountTarget, step.Provenance.Path.String())
	if err != nil {
		t.Fatalf("provenance path %q: %v", step.Provenance.Path, err)
	}
	hostPath := filepath.Join(outDir, rel)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// --------------------------------------------------------------------------.
// Negative: structural invariants enforced by Build.
// --------------------------------------------------------------------------.

func TestBuild_RejectsNestedInputMounts(t *testing.T) {
	p := &lane.Lane{
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name: "src", Image: "img@sha256:" + strings.Repeat("a", 64),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: "/out/tree"}},
			},
			{
				Name: "deps", Image: "img@sha256:" + strings.Repeat("b", 64),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "modules", Type: "directory", Path: "/out/modules"}},
			},
			{
				Name: "build", Image: "img@sha256:" + strings.Repeat("c", 64),
				Args: []string{}, Env: map[string]string{},
				Inputs: []lane.InputRef{
					{Name: "tree", From: "src.tree", Mount: "/work"},
					{Name: "deps", From: "deps.modules", Mount: "/work/node_modules"},
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
				Name: "src", Image: "img@sha256:" + strings.Repeat("a", 64),
				Args: []string{}, Env: map[string]string{},
				Outputs: []lane.OutputSpec{{Name: "tree", Type: "directory", Path: "/out/tree"}},
				Provenance: &lane.ProvenanceSpec{
					Type: "git",
					Path: "/etc/passwd.json",
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
steps:
  - name: build
    image: img@sha256:` + strings.Repeat("a", 64) + `
    args: []
    env: {}
    inputs: []
    sources:
      - { path: ".", mount: /src }
    outputs:
      - { name: bin, type: file, path: /out/bin }
`
	tmpFile := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(tmpFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := lane.Parse(tmpFile)
	if err == nil {
		t.Fatal("expected parse error: 'sources' field does not exist in schema")
	}
}

// --------------------------------------------------------------------------.
// Provenance capture: validate + record + collect through lane state.
// --------------------------------------------------------------------------.

func TestProvenanceCapture_EndToEnd(t *testing.T) {
	p, err := lane.Parse("testdata/hugo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}

	state := lane.NewState()

	// Simulate provenance capture for steps that declare provenance.
	// This exercises ValidateProvenance → RecordProvenance → CollectProvenance.
	for _, stepName := range dag.Order {
		step := dag.Steps[stepName]
		if step.Provenance == nil {
			continue
		}
		raw := fakeProvenanceJSON(t, step.Provenance.Type)
		rec, err := lane.ValidateProvenance(step.Provenance.Type, raw)
		if err != nil {
			t.Fatalf("ValidateProvenance(%s): %v", stepName, err)
		}
		if err := state.RecordProvenance(stepName, rec); err != nil {
			t.Fatalf("RecordProvenance(%s): %v", stepName, err)
		}
	}

	// deploy traverses the full DAG: deploy → pack_site → build → workspace → {source, npm_install}.
	// source has provenance; CollectProvenance from deploy should find it.
	records := state.CollectProvenance(dag, "deploy")
	if len(records) == 0 {
		t.Fatal("expected at least one provenance record from upstream source step")
	}
	if records[0].ProvenanceType() != "git" {
		t.Errorf("expected git provenance, got %q", records[0].ProvenanceType())
	}
	if records[0].IsSigned() {
		t.Error("expected IsSigned() == false for unsigned record")
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
