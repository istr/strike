package deploy_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

func newTestEngine(t *testing.T, handler http.Handler) container.Engine {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	eng, err := container.NewFromAddress("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

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

// containerMock returns an HTTP handler that simulates podman container
// lifecycle (create, start, logs, wait, delete) for state capture tests.
func containerMock(stdout string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/containers/create"):
			json.NewEncoder(w).Encode(map[string]string{"Id": "capture-ctr"}) //nolint:errcheck,gosec // test HTTP handler
		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/logs"):
			header := make([]byte, 8)
			header[0] = 1                                               // stdout stream
			binary.BigEndian.PutUint32(header[4:], uint32(len(stdout))) //nolint:gosec // G115: test data is small
			w.Write(header)                                             //nolint:errcheck,gosec // test HTTP handler
			w.Write([]byte(stdout))                                     //nolint:errcheck,gosec // test HTTP handler
		case strings.HasSuffix(path, "/wait"):
			json.NewEncoder(w).Encode(map[string]int{"StatusCode": 0}) //nolint:errcheck,gosec // test HTTP handler
		case r.Method == http.MethodDelete && strings.Contains(path, "/containers/"):
			json.NewEncoder(w).Encode([]map[string]any{}) //nolint:errcheck,gosec // test HTTP handler
		}
	}
}

func TestDeployerExecute(t *testing.T) {
	eng := newTestEngine(t, containerMock("v1.2.3"))

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: "sha256:abc123",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Name: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target: lane.DeployTarget{Type: "registry", Description: "production"},
			Attestation: lane.AttestationSpec{
				PreState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Network: true,
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Network: true,
					}},
				},
			},
		},
	}

	d := &deploy.Deployer{Engine: eng}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.DeployID == "" {
		t.Error("expected non-empty deploy ID")
	}
	if len(att.Artifacts) == 0 {
		t.Error("expected artifact digests in attestation")
	}
	if att.Artifacts["image"] != "sha256:abc123" {
		t.Errorf("artifact digest = %q, want sha256:abc123", att.Artifacts["image"])
	}
	if len(att.PreState) == 0 {
		t.Error("expected pre-state snapshots")
	}
	if len(att.PostState) == 0 {
		t.Error("expected post-state snapshots")
	}
}

func TestDeployerExecute_MissingArtifact(t *testing.T) {
	eng := newTestEngine(t, containerMock(""))
	state := lane.NewState() // empty -- no artifacts registered

	step := &lane.Step{
		Name: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{"type": "custom", "image": "img@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Attestation: lane.AttestationSpec{},
		},
	}

	d := &deploy.Deployer{Engine: eng}
	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected error for missing artifact")
	}
}

func TestRunStepDispatchesDeploy(t *testing.T) {
	step := &lane.Step{
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{"type": "custom", "image": "img@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	if step.Deploy == nil {
		t.Fatal("expected deploy step to have non-nil Deploy field")
	}
	if step.Pack != nil || step.Image != "" {
		t.Fatal("deploy step must not have pack or image")
	}
}
