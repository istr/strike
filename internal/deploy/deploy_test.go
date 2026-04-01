package deploy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

func TestDetectDrift_NoPrevious(t *testing.T) {
	pre := map[string]deploy.StateSnap{
		"version": {Name: "version", Digest: "sha256:aaa"},
	}
	report := deploy.DetectDrift(pre, nil)
	if report != nil {
		t.Fatal("expected nil drift report for first deploy")
	}
}

func TestDetectDrift_NoDrift(t *testing.T) {
	pre := map[string]deploy.StateSnap{
		"version": {Name: "version", Digest: "sha256:aaa"},
	}
	prev := &deploy.Attestation{
		DeployID: "prev-001",
		PostState: map[string]deploy.StateSnap{
			"version": {Name: "version", Digest: "sha256:aaa"},
		},
	}
	report := deploy.DetectDrift(pre, prev)
	if report == nil {
		t.Fatal("expected non-nil drift report")
	}
	if len(report.Drifted) != 0 {
		t.Fatalf("expected no drift, got %v", report.Drifted)
	}
}

func TestDetectDrift_WithDrift(t *testing.T) {
	pre := map[string]deploy.StateSnap{
		"version": {Name: "version", Digest: "sha256:bbb"},
	}
	prev := &deploy.Attestation{
		DeployID: "prev-001",
		PostState: map[string]deploy.StateSnap{
			"version": {Name: "version", Digest: "sha256:aaa"},
		},
	}
	report := deploy.DetectDrift(pre, prev)
	if report == nil {
		t.Fatal("expected drift report")
	}
	if len(report.Drifted) != 1 || report.Drifted[0] != "version" {
		t.Fatalf("expected drift on 'version', got %v", report.Drifted)
	}
}

func TestAttestationJSON(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "test-001",
		Target:    lane.DeployTarget{Type: "registry", Description: "test"},
		Artifacts: map[string]string{"image": "sha256:abc"},
		PreState: map[string]deploy.StateSnap{
			"version": {Name: "version", Image: "img@sha256:aaa", Digest: "sha256:aaa"},
		},
		PostState: map[string]deploy.StateSnap{
			"version": {Name: "version", Image: "img@sha256:aaa", Digest: "sha256:bbb"},
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
	id1 := deploy.GenerateDeployID("test")
	id2 := deploy.GenerateDeployID("test")
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
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := deploy.ResolveKubeconfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolveKubeconfig_ExplicitMissing(t *testing.T) {
	_, err := deploy.ResolveKubeconfig("/nonexistent/kubeconfig")
	if err == nil {
		t.Fatal("expected error for missing explicit path")
	}
}

func TestResolveKubeconfig_EnvSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)

	got, err := deploy.ResolveKubeconfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolveKubeconfig_EnvMissing(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")

	_, err := deploy.ResolveKubeconfig("")
	if err == nil {
		t.Fatal("expected error for missing $KUBECONFIG path")
	}
}

func TestResolveKubeconfig_DefaultExists(t *testing.T) {
	dir := t.TempDir()
	kubeDir := filepath.Join(dir, ".kube")
	if err := os.MkdirAll(kubeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(kubeDir, "config")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", dir)

	got, err := deploy.ResolveKubeconfig("")
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

	_, err := deploy.ResolveKubeconfig("")
	if err == nil {
		t.Fatal("expected error when no kubeconfig found")
	}
}
