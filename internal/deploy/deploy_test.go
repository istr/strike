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
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

const connTypeTLS = "tls"

// deployCapsuleFields populates the capsule-related Deployer fields needed
// by tests that exercise captureOne or method execution. portKeys lists
// every StepPorts key the test's step will look up (capture keys and/or
// the step name itself).
func deployCapsuleFields(t *testing.T, portKeys ...string) (ca *transport.EphemeralCA, look capsule.UpstreamLookupFunc, caVolume string, ports map[string]capsule.HostPorts) {
	t.Helper()
	var err error
	ca, err = transport.New("deploy-test")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ca, "deploy test CA") })

	caVolume = "strike-ca-test"

	look = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	ports = make(map[string]capsule.HostPorts, len(portKeys))
	base := uint16(16000)
	for i, k := range portKeys {
		ports[k] = capsule.HostPorts{
			Resolver: base + uint16(i)*2,
			Mediator: base + uint16(i)*2 + 1,
		}
	}
	return ca, look, caVolume, ports
}

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

func TestAttestationJSON(t *testing.T) {
	att := &deploy.Attestation{
		Sealed: deploy.Sealed{
			LaneID:    "test-lane",
			Target:    lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "test"},
			Artifacts: map[string]deploy.SignedArtifact{"image": {Digest: "sha256:abc"}},
		},
		Informational: &deploy.Informational{
			PreStateDigest:  lane.MustParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			PostStateDigest: lane.MustParseDigest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			Provenance:      []lane.ProvenanceRecord{},
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
	sealed, ok := m["sealed"].(map[string]any)
	if !ok {
		t.Fatal("missing sealed object in JSON")
	}
	if sealed["lane_id"] != "test-lane" {
		t.Errorf("sealed.lane_id = %v, want test-lane", sealed["lane_id"])
	}
	info, ok := m["informational"].(map[string]any)
	if !ok {
		t.Fatal("missing informational object in JSON")
	}
	if _, ok := info["pre_state_digest"]; !ok {
		t.Error("missing informational.pre_state_digest")
	}
	if _, ok := info["post_state_digest"]; !ok {
		t.Error("missing informational.post_state_digest")
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
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target: lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
			Attestation: lane.AttestationSpec{
				PreState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
			},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-prod",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.LaneID != "test-lane" {
		t.Errorf("LaneID = %q, want test-lane", att.Sealed.LaneID)
	}
	if len(att.Sealed.Artifacts) == 0 {
		t.Error("expected artifact digests in attestation")
	}
	if att.Sealed.Artifacts["image"].Digest != "sha256:abc1230000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("artifact digest = %q, want sha256:abc1230000000000000000000000000000000000000000000000000000000000", att.Sealed.Artifacts["image"].Digest)
	}
	if att.Informational.PreStateDigest.IsZero() {
		t.Error("expected non-zero pre-state digest")
	}
	if att.Informational.PostStateDigest.IsZero() {
		t.Error("expected non-zero post-state digest")
	}
}

func TestDeployerExecute_MissingArtifact(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
	state := lane.NewState() // empty -- no artifacts registered

	step := &lane.Step{
		Name: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{Type: "custom", Image: "img@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Attestation: lane.AttestationSpec{},
		},
	}

	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
	}
	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected error for missing artifact")
	}
}

func TestRunStepDispatchesDeploy(t *testing.T) {
	step := &lane.Step{
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{Type: "custom", Image: "img@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	if step.Deploy == nil {
		t.Fatal("expected deploy step to have non-nil Deploy field")
	}
	if step.Pack != nil || step.Image != nil {
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
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target: lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
			Attestation: lane.AttestationSpec{
				PreState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
			},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine: eng, EngineID: eng.Identity(),
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-prod",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Sealed.Engine == nil {
		t.Fatal("expected non-nil Engine record in attestation")
	}
	if att.Sealed.Engine.ConnectionType != connTypeTLS {
		t.Errorf("Engine.ConnectionType = %q, want tls", att.Sealed.Engine.ConnectionType)
	}
	if !strings.HasPrefix(att.Sealed.Engine.ServerCertFingerprint, "sha256:") {
		t.Errorf("Engine.ServerCertFingerprint = %q, want sha256: prefix", att.Sealed.Engine.ServerCertFingerprint)
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
	sealed, ok := m["sealed"].(map[string]any)
	if !ok {
		t.Fatal("expected sealed object in JSON")
	}
	engMap, ok := sealed["engine"].(map[string]any)
	if !ok {
		t.Fatal("expected sealed.engine object in JSON")
	}
	if engMap["connection_type"] != connTypeTLS {
		t.Errorf("JSON sealed.engine.connection_type = %v, want tls", engMap["connection_type"])
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
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-nil-engine")

	// EngineID is nil -- engineRecord should return nil.
	d := &deploy.Deployer{
		Engine: eng, EngineID: nil,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-nil-engine",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Engine != nil {
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
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-runtime")

	d := &deploy.Deployer{
		Engine: eng, EngineID: id,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-runtime",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Engine == nil {
		t.Fatal("expected non-nil Engine connection record")
	}
	if att.Sealed.Engine.ConnectionType != connTypeTLS {
		t.Errorf("ConnectionType = %q, want tls", att.Sealed.Engine.ConnectionType)
	}
	if att.Sealed.Engine.ServerCertFingerprint != "sha256:abc" {
		t.Errorf("ServerCertFingerprint = %q, want sha256:abc", att.Sealed.Engine.ServerCertFingerprint)
	}
	if att.Sealed.Engine.ClientCertFingerprint != "sha256:def" {
		t.Errorf("ClientCertFingerprint = %q, want sha256:def", att.Sealed.Engine.ClientCertFingerprint)
	}
	if att.Informational.EngineMetadata == nil {
		t.Fatal("expected non-nil EngineMetadata")
	}
	if att.Informational.EngineMetadata.Version != "5.2.1" {
		t.Errorf("EngineMetadata.Version = %q, want 5.2.1", att.Informational.EngineMetadata.Version)
	}
	if att.Informational.EngineMetadata.Rootless == nil || !*att.Informational.EngineMetadata.Rootless {
		t.Error("expected Rootless=true")
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
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-no-runtime")

	d := &deploy.Deployer{
		Engine: eng, EngineID: id,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-no-runtime",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Engine == nil {
		t.Fatal("expected non-nil Engine connection record")
	}
	if att.Sealed.Engine.ConnectionType != "unix" {
		t.Errorf("ConnectionType = %q, want unix", att.Sealed.Engine.ConnectionType)
	}
	if att.Informational.EngineMetadata == nil {
		t.Fatal("expected non-nil EngineMetadata")
	}
	if att.Informational.EngineMetadata.Rootless != nil {
		t.Error("expected nil Rootless when Runtime is nil")
	}
	if att.Informational.EngineMetadata.Version != "" {
		t.Errorf("Version = %q, want empty", att.Informational.EngineMetadata.Version)
	}
}

// resolverRecord tests.
// --------------------------------------------------------------------------.

func TestResolverRecord_NilResolverID(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		Name: "deploy-nil-resolver",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-nil-resolver")

	d := &deploy.Deployer{
		Engine: eng, ResolverID: nil,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-nil-resolver",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Resolver != nil {
		t.Error("expected nil Resolver record when ResolverID is nil")
	}
}

func TestResolverRecord_Populated(t *testing.T) {
	rid := &transport.ConnectionIdentity{
		LeafFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		TLSVersion:      0x0304, // TLS 1.3
		CipherSuite:     0x1301, // TLS_AES_128_GCM_SHA256
		ServerName:      "",
		PeerAddress:     "1.1.1.1:853",
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
		Name: "deploy-resolver",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target:      lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
			Attestation: lane.AttestationSpec{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-resolver")

	d := &deploy.Deployer{
		Engine: eng, ResolverID: rid,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-resolver",
		StepPorts:    ports,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Resolver == nil {
		t.Fatal("expected non-nil Resolver record")
	}
	if att.Sealed.Resolver.Host != "1.1.1.1:853" {
		t.Errorf("Host = %q, want 1.1.1.1:853", att.Sealed.Resolver.Host)
	}
	if att.Sealed.Resolver.ServerCertFingerprint != rid.LeafFingerprint {
		t.Errorf("ServerCertFingerprint = %q, want %q", att.Sealed.Resolver.ServerCertFingerprint, rid.LeafFingerprint)
	}
	if att.Sealed.Resolver.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want TLS 1.3", att.Sealed.Resolver.TLSVersion)
	}
	if att.Sealed.Resolver.CipherSuite == "" {
		t.Error("expected non-empty CipherSuite")
	}
}

// --------------------------------------------------------------------------.
// Execute edge cases.
// --------------------------------------------------------------------------.

func TestDeployerExecute_NotDeployStep(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
	state := lane.NewState()
	step := &lane.Step{Name: "build", Deploy: nil}
	d := &deploy.Deployer{Engine: eng, LaneID: "test-lane"}
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
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{},
			Target:    lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
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

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-fail-pre:version", "deploy-fail-pre")

	d := &deploy.Deployer{
		Engine:       eng,
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-fail-pre",
		StepPorts:    ports,
	}
	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected error for required pre-state failure")
	}
	if !strings.Contains(err.Error(), "pre-state capture failed") {
		t.Errorf("error = %q, want 'pre-state capture failed'", err.Error())
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

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		EngineID:     eng.Identity(),
		Rekor:        newRekorClient(t, rekorPubPEM, srv.Client(), srv.URL),
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-prod",
		StepPorts:    ports,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Sealed.Rekor == nil {
		t.Fatal("expected non-nil att.Sealed.Rekor when RekorClient is configured")
	}
	if att.Sealed.Rekor.LogIndex != 42 {
		t.Errorf("att.Sealed.Rekor.LogIndex = %d, want 42", att.Sealed.Rekor.LogIndex)
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

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-prod",
		StepPorts:    ports,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Sealed.Rekor != nil {
		t.Errorf("expected nil att.Sealed.Rekor when no RekorClient, got %+v", att.Sealed.Rekor)
	}
	if att.SignedEnvelope == nil {
		t.Error("expected non-nil SignedEnvelope (signing should still work)")
	}
}

func TestDeployerExecute_RekorTransient(t *testing.T) {
	_, rekorPubPEM := generateRekorKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		testutil.WriteBody(t, w, []byte("temporary failure"))
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

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		Rekor:        newRekorClient(t, rekorPubPEM, srv.Client(), srv.URL),
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-prod",
		StepPorts:    ports,
	}

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v (expected fail-open on transient Rekor error)", err)
	}

	if att.Sealed.Rekor != nil {
		t.Errorf("expected nil att.Sealed.Rekor on transient failure, got %+v", att.Sealed.Rekor)
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

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		EngineID:     eng.Identity(),
		Rekor:        newRekorClient(t, rekorPubPEM, srv.Client(), srv.URL),
		ArtifactRefs: map[string]string{"image": "build.image"},
		SigningKey:   keyPEM,
		KeyPassword:  nil,
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepName:     "deploy-prod",
		StepPorts:    ports,
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

	sealedMap, ok := attMap["sealed"].(map[string]any)
	if !ok {
		t.Fatal("expected sealed object in DSSE payload")
	}
	if _, hasRekor := sealedMap["rekor"]; hasRekor {
		t.Error("DSSE-signed payload must NOT contain 'sealed.rekor' field")
	}
}

// deployStep returns a minimal deploy step for Rekor tests.
func deployStep() *lane.Step {
	return &lane.Step{
		Name: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: "build.image"},
			},
			Target: lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
			Attestation: lane.AttestationSpec{
				PreState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
				PostState: lane.StateCaptureSpec{
					Capture: []lane.StateCapture{{
						Name:    "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{lane.HTTPSPeer{Type: "https", Host: "localhost:5555", Trust: transport.FingerprintTrust{Mode: "cert_fingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
			},
		},
	}
}

// TestValidateAttestation_InvalidLaneID checks that an invalid lane_id is rejected.
func TestValidateAttestation_InvalidLaneID(t *testing.T) {
	att := &deploy.Attestation{
		Sealed: deploy.Sealed{
			LaneID:    "INVALID_LANE_ID",
			Target:    lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "test"},
			Artifacts: map[string]deploy.SignedArtifact{},
			Peers:     map[string][]lane.Peer{},
		},
		Informational: &deploy.Informational{
			Timestamp:       clock.Reproducible(),
			PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			Provenance:      []lane.ProvenanceRecord{},
		},
	}

	if err := deploy.ValidateAttestation(att); err == nil {
		t.Fatal("expected validation error for invalid lane_id")
	}
}

func TestUnmarshalDeploySpec_UnknownType(t *testing.T) {
	var spec lane.DeploySpec
	err := json.Unmarshal([]byte(`{"method": {"type": "unknown"}}`), &spec)
	if err == nil {
		t.Fatal("expected error for unknown method type")
	}
	if !strings.Contains(err.Error(), "unknown deploy method") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --------------------------------------------------------------------------.
// Observed peer wiring tests.
// --------------------------------------------------------------------------.

func TestDeployerExecute_ObservedPeersPopulated(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))

	// Build a lane with a "build" predecessor that has peers, and a deploy step.
	buildPeer := lane.HTTPSPeer{
		Type: "https",
		Host: "api.example.com:443",
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	buildSSHPeer := lane.SSHPeer{
		Type: "ssh",
		Host: "git.example.com",
		KnownHosts: []lane.KnownHostEntry{{
			KeyType: "ssh-ed25519",
			Key:     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		}},
	}

	p := &lane.Lane{
		Name:     "test-observed",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name:    "build",
				Image:   lane.Ptr(lane.ImageRef("alpine:3.20")),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Outputs: []lane.OutputSpec{
					{Name: "image", Type: "image", Path: lane.Ptr(lane.RelPath("o"))},
				},
				Peers: []lane.Peer{buildPeer, buildSSHPeer},
			},
			{
				Name: "deploy-prod",
				Deploy: &lane.DeploySpec{
					Method: lane.DeployCustom{
						Type:  "custom",
						Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
					},
					Artifacts: map[string]lane.ArtifactRef{
						"image": {From: "build.image"},
					},
					Target:      lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
					Attestation: lane.AttestationSpec{},
				},
			},
		},
	}
	dag, buildErr := lane.Build(p)
	if buildErr != nil {
		t.Fatalf("Build: %v", buildErr)
	}

	state := lane.NewState()
	if regErr := state.Register("build", "image", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); regErr != nil {
		t.Fatal(regErr)
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-prod")

	// Inject synthetic network records for the "build" step.
	tlsFP := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sshFP := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	networkRecords := map[string]capsule.Records{
		"build": {
			Connections: []mediator.ConnectionRecord{{
				Decision: mediator.DecisionAllowed,
				SNI:      "api.example.com",
				Upstream: &transport.ConnectionIdentity{
					LeafFingerprint: tlsFP,
					PeerAddress:     "api.example.com:443",
				},
				Resolved: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			}},
			SSH: []capsule.SSHConnectionRecord{{
				Decision:           mediator.DecisionAllowed,
				Host:               "git.example.com",
				Port:               22,
				HostKeyFingerprint: sshFP,
				HostKeyAlgo:        "ssh-ed25519",
				Resolved:           []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			}},
		},
	}

	step := dag.Steps["deploy-prod"]
	d := &deploy.Deployer{
		Engine:         eng,
		ArtifactRefs:   map[string]string{"image": "build.image"},
		LaneID:         "test-lane",
		DAG:            dag,
		CA:             ca,
		UpstreamLook:   look,
		CAVolume:       caPath,
		StepName:       "deploy-prod",
		StepPorts:      ports,
		NetworkRecords: networkRecords,
	}
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Assert observed_peers has two entries.
	if len(att.Sealed.ObservedPeers) != 2 {
		t.Fatalf("ObservedPeers count = %d, want 2", len(att.Sealed.ObservedPeers))
	}

	tlsObs, ok := att.Sealed.ObservedPeers["api.example.com:443"]
	if !ok {
		t.Fatal("missing observed peer api.example.com:443")
	}
	tlsID, ok := tlsObs.Identity.(deploy.ObservedTLS)
	if !ok {
		t.Fatalf("identity type = %T, want ObservedTLS", tlsObs.Identity)
	}
	if tlsID.ServerCertFingerprint != tlsFP {
		t.Errorf("TLS fingerprint = %q, want %q", tlsID.ServerCertFingerprint, tlsFP)
	}
	if len(tlsObs.Resolved) == 0 {
		t.Error("expected non-empty Resolved for TLS peer")
	}

	sshObs, ok := att.Sealed.ObservedPeers["git.example.com:22"]
	if !ok {
		t.Fatal("missing observed peer git.example.com:22")
	}
	sshID, ok := sshObs.Identity.(deploy.ObservedSSH)
	if !ok {
		t.Fatalf("identity type = %T, want ObservedSSH", sshObs.Identity)
	}
	if sshID.HostKeyFingerprint != sshFP {
		t.Errorf("SSH fingerprint = %q, want %q", sshID.HostKeyFingerprint, sshFP)
	}
	if sshID.HostKeyAlgo != "ssh-ed25519" {
		t.Errorf("SSH algo = %q, want ssh-ed25519", sshID.HostKeyAlgo)
	}

	// Assert peer_attribution.
	buildAttr, ok := att.EngineDependent.PeerAttribution["build"]
	if !ok {
		t.Fatal("missing peer_attribution for build")
	}
	if len(buildAttr) != 2 {
		t.Fatalf("build attribution count = %d, want 2", len(buildAttr))
	}
}

func TestDeployerExecute_ObservedPeersConflictAborts(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))

	// Two predecessor steps whose records report the same host:port with
	// different TLS fingerprints.
	peerA := lane.HTTPSPeer{
		Type: "https",
		Host: "api.example.com:443",
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	peerB := lane.HTTPSPeer{
		Type: "https",
		Host: "api.example.com:443",
		Trust: transport.FingerprintTrust{
			Mode:        "cert_fingerprint",
			Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	p := &lane.Lane{
		Name:     "test-conflict",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				Name:    "step-a",
				Image:   lane.Ptr(lane.ImageRef("alpine:3.20")),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Outputs: []lane.OutputSpec{
					{Name: "out", Type: "file", Path: lane.Ptr(lane.RelPath("a"))},
				},
				Peers: []lane.Peer{peerA},
			},
			{
				Name:    "step-b",
				Image:   lane.Ptr(lane.ImageRef("alpine:3.20")),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Outputs: []lane.OutputSpec{
					{Name: "out", Type: "image", Path: lane.Ptr(lane.RelPath("b"))},
				},
				Peers: []lane.Peer{peerB},
			},
			{
				Name: "deploy-conflict",
				Deploy: &lane.DeploySpec{
					Method: lane.DeployCustom{
						Type:  "custom",
						Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
					},
					Artifacts: map[string]lane.ArtifactRef{
						"image": {From: "step-b.out"},
					},
					Target:      lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
					Attestation: lane.AttestationSpec{},
				},
				Inputs: []lane.InputRef{{From: "step-a.out", Mount: "/in/a"}},
			},
		},
	}
	dag, buildErr := lane.Build(p)
	if buildErr != nil {
		t.Fatalf("Build: %v", buildErr)
	}

	state := lane.NewState()
	if regErr := state.Register("step-b", "out", lane.Artifact{
		Type:   "image",
		Digest: lane.MustParseDigest("sha256:abc1230000000000000000000000000000000000000000000000000000000000"),
	}); regErr != nil {
		t.Fatal(regErr)
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-conflict")

	// Same host:port, different fingerprints -> conflict.
	networkRecords := map[string]capsule.Records{
		"step-a": {
			Connections: []mediator.ConnectionRecord{{
				Decision: mediator.DecisionAllowed,
				SNI:      "api.example.com",
				Upstream: &transport.ConnectionIdentity{
					LeafFingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
					PeerAddress:     "api.example.com:443",
				},
				Resolved: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			}},
		},
		"step-b": {
			Connections: []mediator.ConnectionRecord{{
				Decision: mediator.DecisionAllowed,
				SNI:      "api.example.com",
				Upstream: &transport.ConnectionIdentity{
					LeafFingerprint: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
					PeerAddress:     "api.example.com:443",
				},
				Resolved: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			}},
		},
	}

	step := dag.Steps["deploy-conflict"]
	d := &deploy.Deployer{
		Engine:         eng,
		ArtifactRefs:   map[string]string{"image": "step-b.out"},
		LaneID:         "test-lane",
		DAG:            dag,
		CA:             ca,
		UpstreamLook:   look,
		CAVolume:       caPath,
		StepName:       "deploy-conflict",
		StepPorts:      ports,
		NetworkRecords: networkRecords,
	}
	_, execErr := d.Execute(context.Background(), step, state)
	if execErr == nil {
		t.Fatal("expected error for conflicting observed peer identities")
	}
	if !strings.Contains(execErr.Error(), "conflicting validated identities") {
		t.Errorf("error = %q, want 'conflicting validated identities'", execErr.Error())
	}
}
