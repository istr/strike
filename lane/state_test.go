package lane

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRegisterAndResolve(t *testing.T) {
	s := NewState()

	a := Artifact{
		Type:      "file",
		Digest:    "sha256:abc123",
		Size:      1024,
		LocalPath: "/tmp/out/binary",
	}

	if err := s.Register("build", "binary", a); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := s.Resolve("build.binary")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Digest != a.Digest {
		t.Errorf("digest = %q, want %q", got.Digest, a.Digest)
	}
	if got.Size != a.Size {
		t.Errorf("size = %d, want %d", got.Size, a.Size)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := NewState()
	a := Artifact{Digest: "sha256:abc123", Type: "file"}

	if err := s.Register("build", "binary", a); err != nil {
		t.Fatal(err)
	}
	if err := s.Register("build", "binary", a); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestRegisterMissingDigest(t *testing.T) {
	s := NewState()
	a := Artifact{Type: "file"}

	if err := s.Register("build", "binary", a); err == nil {
		t.Fatal("expected error on missing digest")
	}
}

func TestResolveMissing(t *testing.T) {
	s := NewState()
	_, err := s.Resolve("nonexistent.output")
	if err == nil {
		t.Fatal("expected error on missing reference")
	}
}

func TestRecordStep(t *testing.T) {
	s := NewState()
	r := StepResult{
		Name:      "build",
		StepType:  "run",
		StartedAt: time.Now(),
		Duration:  5 * time.Second,
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
	s := NewState()
	_ = s.Register("build", "binary", Artifact{
		Type:   "file",
		Digest: "sha256:abc123",
		Size:   1024,
	})
	s.RecordStep(StepResult{
		Name:     "build",
		StepType: "run",
		Outputs:  map[string]string{"binary": "sha256:abc123"},
	})

	data, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["artifacts"]; !ok {
		t.Error("missing artifacts key in JSON")
	}
	if _, ok := m["steps"]; !ok {
		t.Error("missing steps key in JSON")
	}
}
