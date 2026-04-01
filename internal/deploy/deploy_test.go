package deploy

import (
	"encoding/json"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestDetectDrift_NoPrevious(t *testing.T) {
	pre := map[string]StateSnap{
		"version": {Name: "version", Digest: "sha256:aaa"},
	}
	report := detectDrift(pre, nil)
	if report != nil {
		t.Fatal("expected nil drift report for first deploy")
	}
}

func TestDetectDrift_NoDrift(t *testing.T) {
	pre := map[string]StateSnap{
		"version": {Name: "version", Digest: "sha256:aaa"},
	}
	prev := &Attestation{
		DeployID: "prev-001",
		PostState: map[string]StateSnap{
			"version": {Name: "version", Digest: "sha256:aaa"},
		},
	}
	report := detectDrift(pre, prev)
	if report == nil {
		t.Fatal("expected non-nil drift report")
	}
	if len(report.Drifted) != 0 {
		t.Fatalf("expected no drift, got %v", report.Drifted)
	}
}

func TestDetectDrift_WithDrift(t *testing.T) {
	pre := map[string]StateSnap{
		"version": {Name: "version", Digest: "sha256:bbb"},
	}
	prev := &Attestation{
		DeployID: "prev-001",
		PostState: map[string]StateSnap{
			"version": {Name: "version", Digest: "sha256:aaa"},
		},
	}
	report := detectDrift(pre, prev)
	if report == nil {
		t.Fatal("expected drift report")
	}
	if len(report.Drifted) != 1 || report.Drifted[0] != "version" {
		t.Fatalf("expected drift on 'version', got %v", report.Drifted)
	}
}

func TestAttestationJSON(t *testing.T) {
	att := &Attestation{
		DeployID:  "test-001",
		Target:    lane.DeployTarget{Type: "registry", Description: "test"},
		Artifacts: map[string]string{"image": "sha256:abc"},
		PreState: map[string]StateSnap{
			"version": {Name: "version", Type: "command", Digest: "sha256:aaa"},
		},
		PostState: map[string]StateSnap{
			"version": {Name: "version", Type: "command", Digest: "sha256:bbb"},
		},
	}

	data, err := att.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["deploy_id"] != "test-001" {
		t.Errorf("deploy_id = %v, want test-001", m["deploy_id"])
	}
	if _, ok := m["pre_state"]; !ok {
		t.Error("missing pre_state")
	}
	if _, ok := m["post_state"]; !ok {
		t.Error("missing post_state")
	}
}

func TestGenerateDeployID(t *testing.T) {
	id1 := generateDeployID("test")
	id2 := generateDeployID("test")
	if id1 == id2 {
		t.Fatal("deploy IDs should be unique")
	}
	if len(id1) != 16 {
		t.Fatalf("deploy ID length = %d, want 16", len(id1))
	}
}
