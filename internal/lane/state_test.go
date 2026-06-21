package lane_test

import (
	"encoding/json"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
)

func TestRegisterAndResolve(t *testing.T) {
	s := lane.NewState()

	imageRef := "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000"
	h := lane.OutputHandle{ImageRef: imageRef}

	if err := s.Register("build", "binary", h); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := s.Resolve("build.binary")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ImageRef != imageRef {
		t.Errorf("imageRef = %q, want %q", got.ImageRef, imageRef)
	}
	digest, err := got.ManifestDigest()
	if err != nil {
		t.Fatalf("ManifestDigest: %v", err)
	}
	want := lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000")
	if digest != want {
		t.Errorf("digest = %q, want %q", digest, want)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := lane.NewState()
	h := lane.OutputHandle{ImageRef: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000"}

	if err := s.Register("build", "binary", h); err != nil {
		t.Fatal(err)
	}
	if err := s.Register("build", "binary", h); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestRegisterMissingImageRef(t *testing.T) {
	s := lane.NewState()
	h := lane.OutputHandle{}

	if err := s.Register("build", "binary", h); err == nil {
		t.Fatal("expected error on missing image ref")
	}
}

func TestResolveMissing(t *testing.T) {
	s := lane.NewState()
	_, err := s.Resolve("nonexistent.output")
	if err == nil {
		t.Fatal("expected error on missing reference")
	}
}

func TestRecordStep(t *testing.T) {
	s := lane.NewState()
	r := lane.StepResult{
		Name:      "build",
		StepType:  "run",
		StartedAt: clock.Wall(),
		Duration:  5 * clock.Second,
		Inputs:    map[string]string{"src": "sha256:111"},
		Outputs:   map[string]string{"binary": "sha256:222"},
		ExitCode:  0,
	}
	s.RecordStep(r)

	got, ok := s.Steps["build"]
	if !ok {
		t.Fatal("step not recorded")
	}
	if got.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", got.ExitCode)
	}
}

func TestStateJSON(t *testing.T) {
	s := lane.NewState()
	if err := s.Register("build", "binary", lane.OutputHandle{
		ImageRef: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}
	s.RecordStep(lane.StepResult{
		Name:     "build",
		StepType: "run",
		Outputs:  map[string]string{"binary": "sha256:abc1230000000000000000000000000000000000000000000000000000000000"},
	})

	data, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["outputs"]; !ok {
		t.Error("missing outputs key in JSON")
	}
	if _, ok := m["steps"]; !ok {
		t.Error("missing steps key in JSON")
	}
}
