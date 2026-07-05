package lane_test

import (
	"encoding/json"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
)

func TestRegisterAndResolve(t *testing.T) {
	s := lane.NewState()

	imageRef := "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000"
	h := output.ImageHandle{Ref: imageRef}

	if err := s.Register("build", "binary", h); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := s.Resolve("build.binary")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ImageRef() != imageRef {
		t.Errorf("imageRef = %q, want %q", got.ImageRef(), imageRef)
	}
	digest, err := output.ManifestDigest(got)
	if err != nil {
		t.Fatalf("ManifestDigest: %v", err)
	}
	want := primitive.DigestFromHex("abc1230000000000000000000000000000000000000000000000000000000000")
	if digest != want {
		t.Errorf("digest = %q, want %q", digest, want)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := lane.NewState()
	h := output.ImageHandle{Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000"}

	if err := s.Register("build", "binary", h); err != nil {
		t.Fatal(err)
	}
	if err := s.Register("build", "binary", h); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestRegisterMissingImageRef(t *testing.T) {
	s := lane.NewState()
	h := output.ImageHandle{}

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
	s.RecordStep(lane.StepResult{
		ID:        "build",
		StepType:  "run",
		StartedAt: clock.Wall(),
		Duration:  5 * clock.Second,
		Outputs:   map[string]string{"binary": "sha256:222"},
		ExitCode:  0,
	})

	var m map[string]struct {
		Result *lane.StepResult `json:"result"`
	}
	data, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec, ok := m["build"]
	if !ok || rec.Result == nil {
		t.Fatal("step result not recorded")
	}
	if rec.Result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", rec.Result.ExitCode)
	}
}

func TestStateJSON(t *testing.T) {
	s := lane.NewState()
	if err := s.Register("build", "binary", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}
	s.RecordStep(lane.StepResult{
		ID:       "build",
		StepType: "run",
		Outputs:  map[string]string{"binary": "sha256:abc1230000000000000000000000000000000000000000000000000000000000"},
	})

	data, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var m map[string]map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	build, ok := m["build"]
	if !ok {
		t.Fatal("missing build step in JSON")
	}
	if _, ok := build["outputs"]; !ok {
		t.Error("missing outputs in build record")
	}
	if _, ok := build["result"]; !ok {
		t.Error("missing result in build record")
	}
}
