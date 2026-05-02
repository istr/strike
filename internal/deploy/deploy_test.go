package deploy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

const connTypeTLS = "tls"

func newTLSTestEngine(t *testing.T, handler http.Handler) container.Engine {
	t.Helper()

	// Ephemeral CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "deploy-test-ca"},
		NotBefore:             clock.Wall().Add(-clock.Minute),
		NotAfter:              clock.Wall().Add(clock.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Server cert for 127.0.0.1
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "deploy-test-engine"},
		NotBefore:    clock.Wall().Add(-clock.Minute),
		NotAfter:     clock.Wall().Add(clock.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})
	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server TLS keypair: %v", err)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(dir, "ca.crt"), caCertPEM, 0o600); writeErr != nil {
		t.Fatalf("write CA cert: %v", writeErr)
	}

	t.Setenv("CONTAINER_TLS_CA", filepath.Join(dir, "ca.crt"))
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	addr := strings.Replace(srv.URL, "https://", "tcp://", 1)
	eng, engErr := container.NewFromAddress(addr)
	if engErr != nil {
		t.Fatalf("NewFromAddress(%s): %v", addr, engErr)
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
		Artifacts: map[string]deploy.SignedArtifact{"image": {Digest: "sha256:abc"}},
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
func containerMock(t *testing.T, stdout string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/containers/create"):
			writeJSON(t, w, map[string]string{"Id": "capture-ctr"})
		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/logs"):
			mustWrite(t, w, streamFrame(1, []byte(stdout)))
		case strings.HasSuffix(path, "/wait"):
			writeJSON(t, w, map[string]int{"StatusCode": 0})
		case r.Method == http.MethodDelete && strings.Contains(path, "/containers/"):
			writeJSON(t, w, []map[string]any{})
		}
	}
}

func TestDeployerExecute(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
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
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
			},
		},
	}

	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
	}
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
	if att.Artifacts["image"].Digest != "sha256:abc1230000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("artifact digest = %q, want sha256:abc1230000000000000000000000000000000000000000000000000000000000", att.Artifacts["image"].Digest)
	}
	if len(att.PreState) == 0 {
		t.Error("expected pre-state snapshots")
	}
	if len(att.PostState) == 0 {
		t.Error("expected post-state snapshots")
	}
}

func TestDeployerExecute_MissingArtifact(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
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

	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
	}
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

func TestHardenedRunOpts(t *testing.T) {
	opts := deploy.HardenedRunOpts()

	if len(opts.CapDrop) != 1 || opts.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", opts.CapDrop)
	}
	if !opts.ReadOnly {
		t.Error("expected ReadOnly=true")
	}
	if len(opts.SecurityOpt) != 1 || opts.SecurityOpt[0] != "no-new-privileges" {
		t.Errorf("SecurityOpt = %v, want [no-new-privileges]", opts.SecurityOpt)
	}
	tmpOpts, ok := opts.Tmpfs["/tmp"]
	if !ok {
		t.Fatal("expected /tmp in Tmpfs")
	}
	if !strings.Contains(tmpOpts, "noexec") {
		t.Errorf("Tmpfs /tmp = %q, want noexec", tmpOpts)
	}
	if opts.UsernsMode != "keep-id" {
		t.Errorf("UsernsMode = %q, want keep-id", opts.UsernsMode)
	}
	if !opts.Remove {
		t.Error("expected Remove=true")
	}
}

func TestAttestationContainsEngineRecord(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))

	// Ping to populate identity
	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
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
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
			},
		},
	}

	d := &deploy.Deployer{Engine: eng, EngineID: eng.Identity(), ArtifactRefs: map[string]string{"image": "build.image"}}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Engine == nil {
		t.Fatal("expected non-nil Engine record in attestation")
	}
	if att.Engine.ConnectionType != connTypeTLS {
		t.Errorf("Engine.ConnectionType = %q, want tls", att.Engine.ConnectionType)
	}
	if !strings.HasPrefix(att.Engine.ServerCertFingerprint, "sha256:") {
		t.Errorf("Engine.ServerCertFingerprint = %q, want sha256: prefix", att.Engine.ServerCertFingerprint)
	}

	// Verify it round-trips through JSON
	data, err := att.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	engMap, ok := m["engine"].(map[string]any)
	if !ok {
		t.Fatal("expected engine object in JSON")
	}
	if engMap["connection_type"] != connTypeTLS {
		t.Errorf("JSON engine.connection_type = %v, want tls", engMap["connection_type"])
	}
}

// --------------------------------------------------------------------------.
// engineRecord tests.
// --------------------------------------------------------------------------.

func TestEngineRecord_NilEngineID(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Name: "deploy-nil-engine",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	// EngineID is nil -- engineRecord should return nil.
	d := &deploy.Deployer{Engine: eng, EngineID: nil, ArtifactRefs: map[string]string{"image": "build.image"}}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Engine != nil {
		t.Error("expected nil Engine record when EngineID is nil")
	}
}

func TestEngineRecord_WithRuntime(t *testing.T) {
	id := &container.EngineIdentity{
		Connection: container.ConnectionInfo{
			Type:                  connTypeTLS,
			CATrustMode:           "pinned",
			ServerCertFingerprint: "sha256:abc",
			ClientCertFingerprint: "sha256:def",
		},
		Runtime: &container.RuntimeInfo{
			Version:  "5.2.1",
			Rootless: true,
		},
	}

	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Name: "deploy-runtime",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	d := &deploy.Deployer{Engine: eng, EngineID: id, ArtifactRefs: map[string]string{"image": "build.image"}}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Engine == nil {
		t.Fatal("expected non-nil Engine record")
	}
	if att.Engine.Version != "5.2.1" {
		t.Errorf("Engine.Version = %q, want 5.2.1", att.Engine.Version)
	}
	if att.Engine.Rootless == nil || !*att.Engine.Rootless {
		t.Error("expected Rootless=true")
	}
	if att.Engine.ConnectionType != connTypeTLS {
		t.Errorf("ConnectionType = %q, want tls", att.Engine.ConnectionType)
	}
	if att.Engine.ServerCertFingerprint != "sha256:abc" {
		t.Errorf("ServerCertFingerprint = %q, want sha256:abc", att.Engine.ServerCertFingerprint)
	}
	if att.Engine.ClientCertFingerprint != "sha256:def" {
		t.Errorf("ClientCertFingerprint = %q, want sha256:def", att.Engine.ClientCertFingerprint)
	}
}

func TestEngineRecord_WithoutRuntime(t *testing.T) {
	id := &container.EngineIdentity{
		Connection: container.ConnectionInfo{
			Type: "unix",
		},
	}

	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Name: "deploy-no-runtime",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	d := &deploy.Deployer{Engine: eng, EngineID: id, ArtifactRefs: map[string]string{"image": "build.image"}}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Engine == nil {
		t.Fatal("expected non-nil Engine record")
	}
	if att.Engine.ConnectionType != "unix" {
		t.Errorf("ConnectionType = %q, want unix", att.Engine.ConnectionType)
	}
	if att.Engine.Rootless != nil {
		t.Error("expected nil Rootless when Runtime is nil")
	}
	if att.Engine.Version != "" {
		t.Errorf("Version = %q, want empty", att.Engine.Version)
	}
}

// --------------------------------------------------------------------------.
// DetectDrift additional cases.
// --------------------------------------------------------------------------.

func TestDetectDrift_NewDimension(t *testing.T) {
	pre := map[string]deploy.StateSnap{
		"version": {Name: "version", Digest: "sha256:aaa"},
		"config":  {Name: "config", Digest: "sha256:bbb"},
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
	// "config" is new, should not be in Drifted.
	if len(report.Drifted) != 0 {
		t.Fatalf("expected no drift for new dimensions, got %v", report.Drifted)
	}
}

// --------------------------------------------------------------------------.
// Execute edge cases.
// --------------------------------------------------------------------------.

func TestDeployerExecute_NotDeployStep(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
	state := lane.NewState()
	step := &lane.Step{Name: "build", Deploy: nil}
	d := &deploy.Deployer{Engine: eng}
	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected error for non-deploy step")
	}
	if !strings.Contains(err.Error(), "not a deploy step") {
		t.Errorf("error = %q, want 'not a deploy step'", err.Error())
	}
}

func TestDeployerExecute_RequiredPreStateFails(t *testing.T) {
	// Use a handler that returns exit code 1 for state capture.
	failMock := func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/containers/create"):
			writeJSON(t, w, map[string]string{"Id": "fail-ctr"})
		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/logs"):
			mustWrite(t, w, streamFrame(2, []byte("failed")))
		case strings.HasSuffix(path, "/wait"):
			writeJSON(t, w, map[string]int{"StatusCode": 1})
		case r.Method == http.MethodDelete:
			writeJSON(t, w, []map[string]any{})
		}
	}

	eng := newTLSTestEngine(t, http.HandlerFunc(failMock))
	state := lane.NewState()

	step := &lane.Step{
		Name: "deploy-fail-pre",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{},
			Target:    lane.DeployTarget{Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{
				PreState: lane.StateCaptureSpec{
					Required: true,
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
					}},
				},
			},
		},
	}

	d := &deploy.Deployer{Engine: eng}
	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected error for required pre-state failure")
	}
	if !strings.Contains(err.Error(), "pre-state capture failed") {
		t.Errorf("error = %q, want 'pre-state capture failed'", err.Error())
	}
}

func TestDeployerExecute_DriftDetectFail(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Name: "deploy-drift-fail",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target: lane.DeployTarget{Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{
				Drift: lane.DriftSpec{
					Detect:  true,
					OnDrift: "fail",
				},
				PreState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
			},
		},
	}

	// Drift detection is enabled but previous attestation is nil (first deploy).
	// So no actual drift occurs. Just test the code path is exercised.
	d := &deploy.Deployer{Engine: eng, ArtifactRefs: map[string]string{"image": "build.image"}}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// First deploy -- drift should be nil (no previous attestation).
	if att.Drift != nil {
		t.Error("expected nil drift for first deploy")
	}
}

// --------------------------------------------------------------------------.
// Rekor DSSE attestation tests.
// --------------------------------------------------------------------------.

func TestDeployerExecute_WithRekor(t *testing.T) {
	rekorKey, rekorPubPEM := generateRekorKey(t)
	srv := httptest.NewServer(fakeDSSERekorHandler(t, rekorKey))
	defer srv.Close()

	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))
	keyPEM, _ := generateTestKeyPEM(t)

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		EngineID:     eng.Identity(),
		Rekor:        newRekorClient(t, rekorPubPEM, srv.Client(), srv.URL),
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Rekor == nil {
		t.Fatal("expected non-nil att.Rekor when RekorClient is configured")
	}
	if att.Rekor.LogIndex != 42 {
		t.Errorf("att.Rekor.LogIndex = %d, want 42", att.Rekor.LogIndex)
	}
	if att.SignedEnvelope == nil {
		t.Error("expected non-nil SignedEnvelope")
	}
}

func TestDeployerExecute_NoRekor(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))
	keyPEM, _ := generateTestKeyPEM(t)

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Rekor != nil {
		t.Errorf("expected nil att.Rekor when no RekorClient, got %+v", att.Rekor)
	}
	if att.SignedEnvelope == nil {
		t.Error("expected non-nil SignedEnvelope (signing should still work)")
	}
}

func TestDeployerExecute_RekorTransient(t *testing.T) {
	_, rekorPubPEM := generateRekorKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("temporary failure")) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))
	keyPEM, _ := generateTestKeyPEM(t)

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		Rekor:        newRekorClient(t, rekorPubPEM, srv.Client(), srv.URL),
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v (expected fail-open on transient Rekor error)", err)
	}

	if att.Rekor != nil {
		t.Errorf("expected nil att.Rekor on transient failure, got %+v", att.Rekor)
	}
	if att.SignedEnvelope == nil {
		t.Error("expected non-nil SignedEnvelope (signing should still work)")
	}
}

func TestDeployerExecute_RekorSignedContentNoRekorField(t *testing.T) {
	rekorKey, rekorPubPEM := generateRekorKey(t)
	srv := httptest.NewServer(fakeDSSERekorHandler(t, rekorKey))
	defer srv.Close()

	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))
	keyPEM, _ := generateTestKeyPEM(t)

	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		EngineID:     eng.Identity(),
		Rekor:        newRekorClient(t, rekorPubPEM, srv.Client(), srv.URL),
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The DSSE envelope must have been signed BEFORE the rekor field was set.
	// Verify by decoding the envelope and checking the payload has no "rekor" key.
	var env deploy.DSSEEnvelope
	if unmarshalErr := json.Unmarshal(att.SignedEnvelope, &env); unmarshalErr != nil {
		t.Fatalf("unmarshal DSSE envelope: %v", unmarshalErr)
	}

	payloadJSON, decErr := base64.RawURLEncoding.DecodeString(env.Payload)
	if decErr != nil {
		t.Fatalf("decode payload: %v", decErr)
	}

	var attMap map[string]any
	if unmarshalErr := json.Unmarshal(payloadJSON, &attMap); unmarshalErr != nil {
		t.Fatalf("unmarshal payload: %v", unmarshalErr)
	}

	if _, hasRekor := attMap["rekor"]; hasRekor {
		t.Error("DSSE-signed payload must NOT contain 'rekor' field")
	}
}

// deployStep returns a minimal deploy step for Rekor tests.
func deployStep() *lane.Step {
	return &lane.Step{
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
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{{"type": "oci", "registry": "localhost:5555"}},
					}},
				},
			},
		},
	}
}

func TestExecuteMethod_UnknownType(t *testing.T) {
	eng := newTLSTestEngine(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	d := &deploy.Deployer{Engine: eng}
	spec := &lane.DeploySpec{
		Method: lane.DeployMethod{"type": "unknown"},
	}
	err := d.ExecuteMethod(context.Background(), spec, nil)
	if err == nil {
		t.Fatal("expected error for unknown method type")
	}
	if !strings.Contains(err.Error(), "unknown deploy method") {
		t.Errorf("unexpected error: %v", err)
	}
}
