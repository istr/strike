package deploy_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/target"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

const (
	connTypeTLS  = "tls"
	connTypeMTLS = "mtls"
)

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
			Target:    target.Deploy{ID: "prod-1", Type: "registry", Description: "test"},
			Artifacts: map[string]record.Artifact{"image": {Digest: "sha256:abc"}},
		},
		Informational: &deploy.Informational{
			PreStateDigest:  primitive.DigestFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			PostStateDigest: primitive.DigestFromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			Provenance:      []provenance.Record{},
		},
	}

	data, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sealed, ok := m["sealed"].(map[string]any)
	if !ok {
		t.Fatal("missing sealed object in JSON")
	}
	if sealed["laneId"] != "test-lane" {
		t.Errorf("sealed.laneId = %v, want test-lane", sealed["laneId"])
	}
	info, ok := m["informational"].(map[string]any)
	if !ok {
		t.Fatal("missing informational object in JSON")
	}
	if _, ok := info["preStateDigest"]; !ok {
		t.Error("missing informational.preStateDigest")
	}
	if _, ok := info["postStateDigest"]; !ok {
		t.Error("missing informational.postStateDigest")
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
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target: target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
			Recording: lane.StateRecording{
				PreState: lane.CaptureSet{
					Captures: []lane.Capture{{
						ID:      "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
				PostState: lane.CaptureSet{
					Captures: []lane.Capture{{
						ID:      "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
			},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine:       eng,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-prod",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
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
	if att.Informational.PreStateDigest == "" {
		t.Error("expected non-zero pre-state digest")
	}
	if att.Informational.PostStateDigest == "" {
		t.Error("expected non-zero post-state digest")
	}
}

func TestDeployerExecuteRegistryAttachesReferrers(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))

	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host := "localhost:" + u.Port() // ggcr dials 127.0.0.1 via HTTPS; localhost via HTTP

	src := host + "/src:v1"
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err = mutate.AppendLayers(img, static.NewLayer([]byte("artifact"), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	srcRef, err := name.ParseReference(src)
	if err != nil {
		t.Fatalf("parse src: %v", err)
	}
	if writeErr := remote.Write(srcRef, img); writeErr != nil {
		t.Fatalf("seed source image: %v", writeErr)
	}
	imgDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	state := lane.NewState()
	if regErr := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); regErr != nil {
		t.Fatal(regErr)
	}

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployRegistry{
				Type:   "registry",
				Source: src,
				Target: host + "/app:v1",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target: target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
			Recording: lane.StateRecording{
				PreState:  lane.CaptureSet{Captures: []lane.Capture{}},
				PostState: lane.CaptureSet{Captures: []lane.Capture{}},
			},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine:       eng,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-prod",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	if _, execErr := d.Execute(context.Background(), step, state); execErr != nil {
		t.Fatalf("Execute: %v", execErr)
	}

	subjectRef, err := name.NewDigest(host + "/app@" + imgDigest.String())
	if err != nil {
		t.Fatalf("subject digest ref: %v", err)
	}
	index, err := remote.Referrers(subjectRef)
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest: %v", err)
	}
	if len(manifest.Manifests) != 3 {
		t.Fatalf("referrers = %d, want 3", len(manifest.Manifests))
	}
	want := map[string]bool{"sealed": false, "engine-context": false, "informational": false}
	for _, desc := range manifest.Manifests {
		dref, err := name.NewDigest(host + "/app@" + desc.Digest.String())
		if err != nil {
			t.Fatalf("referrer digest ref: %v", err)
		}
		rimg, err := remote.Image(dref)
		if err != nil {
			t.Fatalf("fetch referrer %s: %v", desc.Digest, err)
		}
		rimgMfst, err := rimg.Manifest()
		if err != nil {
			t.Fatalf("referrer manifest %s: %v", desc.Digest, err)
		}
		stmt := rimgMfst.Annotations["dev.strike.statement"]
		if _, ok := want[stmt]; !ok {
			t.Errorf("unexpected statement annotation %q", stmt)
			continue
		}
		want[stmt] = true
	}
	for stmt, ok := range want {
		if !ok {
			t.Errorf("missing referrer for statement %q", stmt)
		}
	}
}

func TestDeployerExecute_MissingArtifact(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
	state := lane.NewState() // empty -- no artifacts registered

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{Type: "custom", Image: "img@sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Recording: lane.StateRecording{},
		},
	}

	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
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
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target: target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
			Recording: lane.StateRecording{
				PreState: lane.CaptureSet{
					Captures: []lane.Capture{{
						ID:      "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
				PostState: lane.CaptureSet{
					Captures: []lane.Capture{{
						ID:      "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
			},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine: eng, EngineID: eng.Identity(),
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-prod",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Sealed.Engine == nil {
		t.Fatal("expected non-nil Engine record in attestation")
	}
	if att.Sealed.Engine.ConnectionType() != connTypeTLS {
		t.Errorf("Engine.ConnectionType = %q, want tls", att.Sealed.Engine.ConnectionType())
	}
	tlsConn, ok := att.Sealed.Engine.(endpoint.EngineTLS)
	if !ok {
		t.Fatalf("Engine type = %T, want endpoint.EngineTLS", att.Sealed.Engine)
	}
	if !strings.HasPrefix(tlsConn.ServerCertFingerprint, "sha256:") {
		t.Errorf("Engine.ServerCertFingerprint = %q, want sha256: prefix", tlsConn.ServerCertFingerprint)
	}

	// Verify it round-trips through JSON
	data, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
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
	if engMap["type"] != connTypeTLS {
		t.Errorf("JSON sealed.engine.type = %v, want tls", engMap["type"])
	}
}

// --------------------------------------------------------------------------.
// engineRecord tests.
// --------------------------------------------------------------------------.

func TestEngineRecord_NilEngineID(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-nil-engine",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target:    target.Deploy{ID: "test-1", Type: "registry", Description: "test"},
			Recording: lane.StateRecording{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-nil-engine")

	// EngineID is nil -- engineRecord should return nil.
	d := &deploy.Deployer{
		Engine: eng, EngineID: nil,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-nil-engine",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
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
			Type:                  connTypeMTLS,
			CATrustType:           "pinned",
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
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-runtime",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target:    target.Deploy{ID: "test-1", Type: "registry", Description: "test"},
			Recording: lane.StateRecording{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-runtime")

	d := &deploy.Deployer{
		Engine: eng, EngineID: id,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-runtime",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Engine == nil {
		t.Fatal("expected non-nil Engine connection record")
	}
	if att.Sealed.Engine.ConnectionType() != connTypeMTLS {
		t.Errorf("ConnectionType = %q, want mtls", att.Sealed.Engine.ConnectionType())
	}
	mtlsConn, ok := att.Sealed.Engine.(endpoint.EngineMTLS)
	if !ok {
		t.Fatalf("Engine type = %T, want endpoint.EngineMTLS", att.Sealed.Engine)
	}
	if mtlsConn.ServerCertFingerprint != "sha256:abc" {
		t.Errorf("ServerCertFingerprint = %q, want sha256:abc", mtlsConn.ServerCertFingerprint)
	}
	if mtlsConn.ClientCertFingerprint != "sha256:def" {
		t.Errorf("ClientCertFingerprint = %q, want sha256:def", mtlsConn.ClientCertFingerprint)
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
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-no-runtime",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target:    target.Deploy{ID: "test-1", Type: "registry", Description: "test"},
			Recording: lane.StateRecording{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-no-runtime")

	d := &deploy.Deployer{
		Engine: eng, EngineID: id,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-no-runtime",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if att.Sealed.Engine == nil {
		t.Fatal("expected non-nil Engine connection record")
	}
	if att.Sealed.Engine.ConnectionType() != "unix" {
		t.Errorf("ConnectionType = %q, want unix", att.Sealed.Engine.ConnectionType())
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

func TestResolverRecord_Populated(t *testing.T) {
	rid := transport.ConnectionIdentity{
		LeafFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		TLSVersion:      0x0304, // TLS 1.3
		CipherSuite:     0x1301, // TLS_AES_128_GCM_SHA256
		ServerName:      "",
		PeerAddress:     endpoint.MustParseAuthority("1.1.1.1:853"),
	}

	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))
	state := lane.NewState()
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-resolver",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target:    target.Deploy{ID: "test-1", Type: "registry", Description: "test"},
			Recording: lane.StateRecording{},
		},
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-resolver")

	d := &deploy.Deployer{
		Engine:     eng,
		LaneDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Resolver: deploy.ResolverProbe{
			Declared: endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("1.1.1.1:853"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}},
			Observed: rid,
		},
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-resolver",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
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
	step := &lane.Step{ID: "build", Deploy: nil}
	d := &deploy.Deployer{Engine: eng, LaneID: "test-lane"}
	deploy.SetProduceBundles(d, stubProduceBundles())
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
		ID: "deploy-fail-pre",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{},
			Target:    target.Deploy{ID: "test-1", Type: "registry", Description: "test"},
			Recording: lane.StateRecording{
				PreState: lane.CaptureSet{
					Required: true,
					Captures: []lane.Capture{{
						ID:      "version",
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
		StepID:       "deploy-fail-pre",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected error for required pre-state failure")
	}
	if !strings.Contains(err.Error(), "pre-state capture failed") {
		t.Errorf("error = %q, want 'pre-state capture failed'", err.Error())
	}
}

// --------------------------------------------------------------------------.
// Keyless bundle tests.
// --------------------------------------------------------------------------.

// stubProduceBundles returns a bundle producer that yields one fake bundle
// per statement, replacing the real keyless chain (covered by the live
// test).
func stubProduceBundles() func(context.Context, lane.KeylessEndpoints, [][]byte) ([][]byte, error) {
	return func(_ context.Context, _ lane.KeylessEndpoints, statements [][]byte) ([][]byte, error) {
		bundles := make([][]byte, len(statements))
		for i := range statements {
			bundles[i] = []byte(fmt.Sprintf(`{"stub":"bundle-%d"}`, i))
		}
		return bundles, nil
	}
}

func TestDeployerExecute_KeylessBundles(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))

	state := lane.NewState()
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		EngineID:     eng.Identity(),
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-prod",
		StepPorts:    ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())

	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if att.Signed == nil {
		t.Fatal("expected non-nil Signed")
	}
	got := map[string][]byte{
		"sealed":         att.Signed.Sealed.Bundle,
		"engine-context": att.Signed.EngineContext.Bundle,
		"informational":  att.Signed.Informational.Bundle,
	}
	want := map[string][]byte{
		"sealed":         []byte(`{"stub":"bundle-0"}`),
		"engine-context": []byte(`{"stub":"bundle-1"}`),
		"informational":  []byte(`{"stub":"bundle-2"}`),
	}
	for name, wantBundle := range want {
		if !bytes.Equal(got[name], wantBundle) {
			t.Errorf("%s bundle = %s, want %s", name, got[name], wantBundle)
		}
	}
}

func TestDeployerExecute_KeylessFailureIsFatal(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.2.3"))

	state := lane.NewState()
	if err := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}

	ca, look, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep()
	d := &deploy.Deployer{
		Engine:       eng,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[string]string{"image": "build.image"},
		LaneID:       "test-lane",
		CA:           ca,
		UpstreamLook: look,
		CAVolume:     caPath,
		StepID:       "deploy-prod",
		StepPorts:    ports,
	}
	wantErr := errors.New("keyless: fulcio unreachable")
	deploy.SetProduceBundles(d, func(_ context.Context, _ lane.KeylessEndpoints, _ [][]byte) ([][]byte, error) {
		return nil, wantErr
	})

	_, err := d.Execute(context.Background(), step, state)
	if err == nil {
		t.Fatal("expected Execute to fail when bundle production fails (fail-closed)")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want wrapped %v", err, wantErr)
	}
}

// deployStep returns a minimal deploy step for Rekor tests.
func deployStep() *lane.Step {
	return &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployCustom{
				Type:  "custom",
				Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			Artifacts: map[string]lane.ArtifactRef{
				"image": {From: lane.StepImageRef{Step: "build"}},
			},
			Target: target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
			Recording: lane.StateRecording{
				PreState: lane.CaptureSet{
					Captures: []lane.Capture{{
						ID:      "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
					}},
				},
				PostState: lane.CaptureSet{
					Captures: []lane.Capture{{
						ID:      "version",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
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
			Target:    target.Deploy{ID: "prod-1", Type: "registry", Description: "test"},
			Artifacts: map[string]record.Artifact{},
			Peers:     map[primitive.Identifier][]lane.Peer{},
		},
		Informational: &deploy.Informational{
			Timestamp:       clock.Reproducible(),
			PreStateDigest:  primitive.DigestFromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			PostStateDigest: primitive.DigestFromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			Provenance:      []provenance.Record{},
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
	buildPeer := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("api.example.com:443"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	buildSSHPeer := endpoint.SSH{
		Type:    "ssh",
		Address: endpoint.MustParseAuthority("git.example.com"),
		KnownHosts: []endpoint.HostKey{{
			KeyType: "ssh-ed25519",
			Key:     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		}},
	}

	p := &lane.Lane{
		Name:     "test-observed",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID:      "build",
				Image:   primitive.ImageRefPtr("alpine:3.20"),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Output:  "image",
				Peers:   []lane.Peer{buildPeer, buildSSHPeer},
			},
			{
				ID: "deploy-prod",
				Deploy: &lane.DeploySpec{
					Method: lane.DeployCustom{
						Type:  "custom",
						Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
					},
					Artifacts: map[string]lane.ArtifactRef{
						"image": {From: lane.StepImageRef{Step: "build"}},
					},
					Target:    target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
					Recording: lane.StateRecording{},
				},
			},
		},
	}
	index, buildErr := lane.IndexSteps(p)
	if buildErr != nil {
		t.Fatalf("IndexSteps: %v", buildErr)
	}
	dag, buildErr := lane.Build(p, index)
	if buildErr != nil {
		t.Fatalf("Build: %v", buildErr)
	}

	state := lane.NewState()
	if regErr := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
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
					PeerAddress:     endpoint.MustParseAuthority("api.example.com:443"),
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

	step := index["deploy-prod"]
	d := &deploy.Deployer{
		Engine:         eng,
		LaneDigest:     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs:   map[string]string{"image": "build.image"},
		LaneID:         "test-lane",
		DAG:            dag,
		CA:             ca,
		UpstreamLook:   look,
		CAVolume:       caPath,
		StepID:         "deploy-prod",
		StepPorts:      ports,
		NetworkRecords: networkRecords,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
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

func TestDeployerExecute_ObservedPeers_HonorsSSHPort(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))

	buildSSHPeer := endpoint.SSH{
		Type:    "ssh",
		Address: endpoint.MustParseAuthority("sshhost.com:222"),
		KnownHosts: []endpoint.HostKey{{
			KeyType: "ssh-ed25519",
			Key:     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		}},
	}

	p := &lane.Lane{
		Name:     "test-ssh-port",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID:      "build",
				Image:   primitive.ImageRefPtr("alpine:3.20"),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Output:  "image",
				Peers:   []lane.Peer{buildSSHPeer},
			},
			{
				ID: "deploy-prod",
				Deploy: &lane.DeploySpec{
					Method: lane.DeployCustom{
						Type:  "custom",
						Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
					},
					Artifacts: map[string]lane.ArtifactRef{
						"image": {From: lane.StepImageRef{Step: "build"}},
					},
					Target:    target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
					Recording: lane.StateRecording{},
				},
			},
		},
	}
	index, buildErr := lane.IndexSteps(p)
	if buildErr != nil {
		t.Fatalf("IndexSteps: %v", buildErr)
	}
	dag, buildErr := lane.Build(p, index)
	if buildErr != nil {
		t.Fatalf("Build: %v", buildErr)
	}

	state := lane.NewState()
	if regErr := state.Register("build", "image", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); regErr != nil {
		t.Fatal(regErr)
	}

	ca, look, caPath, ports := deployCapsuleFields(t, "deploy-prod")

	// The declared port (222) must survive into the observed-peer key; before
	// the port-drop fix, deploy.go's SSH key derivation already used
	// s.Port directly, so this pins that behavior against regression as the
	// TLS-side key derivation changes from string re-parsing to Address.Authority().
	sshFP := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	networkRecords := map[string]capsule.Records{
		"build": {
			SSH: []capsule.SSHConnectionRecord{{
				Decision:           mediator.DecisionAllowed,
				Host:               "sshhost.com",
				Port:               222,
				HostKeyFingerprint: sshFP,
				HostKeyAlgo:        "ssh-ed25519",
				Resolved:           []netip.Addr{netip.MustParseAddr("192.0.2.9")},
			}},
		},
	}

	step := index["deploy-prod"]
	d := &deploy.Deployer{
		Engine:         eng,
		LaneDigest:     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs:   map[string]string{"image": "build.image"},
		LaneID:         "test-lane",
		DAG:            dag,
		CA:             ca,
		UpstreamLook:   look,
		CAVolume:       caPath,
		StepID:         "deploy-prod",
		StepPorts:      ports,
		NetworkRecords: networkRecords,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if _, wrongPort := att.Sealed.ObservedPeers["sshhost.com:22"]; wrongPort {
		t.Error("observed peer recorded under default port 22, want declared port 222")
	}
	obs, ok := att.Sealed.ObservedPeers["sshhost.com:222"]
	if !ok {
		t.Fatalf("missing observed peer sshhost.com:222; got %v", att.Sealed.ObservedPeers)
	}
	sshID, ok := obs.Identity.(deploy.ObservedSSH)
	if !ok {
		t.Fatalf("identity type = %T, want ObservedSSH", obs.Identity)
	}
	if sshID.HostKeyFingerprint != sshFP {
		t.Errorf("HostKeyFingerprint = %q, want %q", sshID.HostKeyFingerprint, sshFP)
	}
}

func TestDeployerExecute_ObservedPeersConflictAborts(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, "v1.0"))

	// Two predecessor steps whose records report the same host:port with
	// different TLS fingerprints.
	peerA := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("api.example.com:443"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	peerB := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("api.example.com:443"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	p := &lane.Lane{
		Name:     "test-conflict",
		Registry: "localhost:5555/test",
		Steps: []lane.Step{
			{
				ID:      "step-a",
				Image:   primitive.ImageRefPtr("alpine:3.20"),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Outputs: []lane.FileOutput{
					{ID: "out", Type: "file", Path: primitive.RelPathPtr("a")},
				},
				Peers: []lane.Peer{peerA},
			},
			{
				ID:      "step-b",
				Image:   primitive.ImageRefPtr("alpine:3.20"),
				Args:    []string{"echo", "ok"},
				Env:     map[string]string{},
				Inputs:  []lane.InputRef{},
				Secrets: []lane.SecretRef{},
				Output:  "image",
				Peers:   []lane.Peer{peerB},
			},
			{
				ID: "deploy-conflict",
				Deploy: &lane.DeploySpec{
					Method: lane.DeployCustom{
						Type:  "custom",
						Image: "runner@sha256:0000000000000000000000000000000000000000000000000000000000000000",
					},
					Artifacts: map[string]lane.ArtifactRef{
						"image": {From: lane.StepImageRef{Step: "step-b"}},
					},
					Target:    target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
					Recording: lane.StateRecording{},
				},
				Inputs: []lane.InputRef{{From: lane.OutputRef{Step: "step-a", Output: "out"}, Mount: "/in/a"}},
			},
		},
	}
	index, buildErr := lane.IndexSteps(p)
	if buildErr != nil {
		t.Fatalf("IndexSteps: %v", buildErr)
	}
	dag, buildErr := lane.Build(p, index)
	if buildErr != nil {
		t.Fatalf("Build: %v", buildErr)
	}

	state := lane.NewState()
	if regErr := state.Register("step-b", "out", output.ImageHandle{
		Ref: "localhost/test/step-b@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
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
					PeerAddress:     endpoint.MustParseAuthority("api.example.com:443"),
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
					PeerAddress:     endpoint.MustParseAuthority("api.example.com:443"),
				},
				Resolved: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			}},
		},
	}

	step := index["deploy-conflict"]
	d := &deploy.Deployer{
		Engine:         eng,
		ArtifactRefs:   map[string]string{"image": "step-b.out"},
		LaneID:         "test-lane",
		DAG:            dag,
		CA:             ca,
		UpstreamLook:   look,
		CAVolume:       caPath,
		StepID:         "deploy-conflict",
		StepPorts:      ports,
		NetworkRecords: networkRecords,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	_, execErr := d.Execute(context.Background(), step, state)
	if execErr == nil {
		t.Fatal("expected error for conflicting observed peer identities")
	}
	if !strings.Contains(execErr.Error(), "conflicting validated identities") {
		t.Errorf("error = %q, want 'conflicting validated identities'", execErr.Error())
	}
}
