package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestResolveKubeconfig_ExplicitExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	os.WriteFile(path, []byte("test"), 0o600)

	got, err := resolveKubeconfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolveKubeconfig_ExplicitMissing(t *testing.T) {
	_, err := resolveKubeconfig("/nonexistent/kubeconfig")
	if err == nil {
		t.Fatal("expected error for missing explicit path")
	}
}

func TestResolveKubeconfig_EnvSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	os.WriteFile(path, []byte("test"), 0o600)
	t.Setenv("KUBECONFIG", path)

	got, err := resolveKubeconfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolveKubeconfig_EnvMissing(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")

	_, err := resolveKubeconfig("")
	if err == nil {
		t.Fatal("expected error for missing $KUBECONFIG path")
	}
}

func TestResolveKubeconfig_DefaultExists(t *testing.T) {
	dir := t.TempDir()
	kubeDir := filepath.Join(dir, ".kube")
	os.MkdirAll(kubeDir, 0o755)
	path := filepath.Join(kubeDir, "config")
	os.WriteFile(path, []byte("test"), 0o600)

	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", dir)

	got, err := resolveKubeconfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolveKubeconfig_NoneFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", dir)

	_, err := resolveKubeconfig("")
	if err == nil {
		t.Fatal("expected error when no kubeconfig found")
	}
}
