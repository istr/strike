package deploy_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry/regtest"
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
func deployCapsuleFields(t *testing.T, portKeys ...string) (ca *transport.EphemeralCA, dialer *transport.Dialer, caVolume string, ports map[string]capsule.HostPorts) {
	t.Helper()
	var err error
	ca, err = transport.New("deploy-test")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ca, "deploy test CA") })

	caVolume = "strike-ca-test"

	dialer = testutil.StartDoTResolver(t, netip.MustParseAddr("127.0.0.1"))

	ports = make(map[string]capsule.HostPorts, len(portKeys))
	base := uint16(16000)
	for i, k := range portKeys {
		ports[k] = capsule.HostPorts{
			Resolver: base + uint16(i)*2,
			Mediator: base + uint16(i)*2 + 1,
		}
	}
	return ca, dialer, caVolume, ports
}

// registryDeployFixture is the shared setup for the tests that must run a
// deploy through executeMethod: a single-layer pushable image, an engine that
// serves it as a layout tar, and a live registry the control plane may write
// to under a pinned leaf fingerprint. Callers supply their own captures.
type registryDeployFixture struct {
	engine container.Engine
	method lane.DeployRegistry
	handle output.ImageHandle
}

// newRegistryDeployFixture builds the fixture. The image is minimal but
// well-formed: the deploy path flattens the pushed payload for cataloging, so
// the layer must be a real tar.
func newRegistryDeployFixture(t *testing.T) registryDeployFixture {
	t.Helper()

	var layerBuf bytes.Buffer
	tw := tar.NewWriter(&layerBuf)
	if hdrErr := tw.WriteHeader(&tar.Header{Name: "artifact", Mode: 0o644, Size: int64(len("payload"))}); hdrErr != nil {
		t.Fatalf("layer tar header: %v", hdrErr)
	}
	if _, wErr := tw.Write([]byte("payload")); wErr != nil {
		t.Fatalf("layer tar content: %v", wErr)
	}
	if closeErr := tw.Close(); closeErr != nil {
		t.Fatalf("layer tar close: %v", closeErr)
	}
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err := mutate.AppendLayers(img, static.NewLayer(layerBuf.Bytes(), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	configHash, err := img.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}
	saved, err := regtest.LayoutTar(img)
	if err != nil {
		t.Fatalf("layout tar: %v", err)
	}

	// The converted tests keep their capture declarations, and captures run
	// containers through this same engine, so everything that is not the
	// image export falls through to the container lifecycle mock.
	lifecycle := containerMock(t, "v1.2.3")
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/get") {
			w.Header().Set("Content-Type", "application/x-tar")
			if _, wErr := w.Write(saved); wErr != nil {
				t.Errorf("write save tar: %v", wErr)
			}
			return
		}
		lifecycle(w, r)
	}))

	srv := httptest.NewTLSServer(ggcrregistry.New(ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	leafSum := sha256.Sum256(srv.Certificate().Raw)

	return registryDeployFixture{
		engine: eng,
		method: lane.DeployRegistry{
			Type: "registry",
			Target: lane.DeployRegistryTarget{
				Type:    "https",
				Address: endpoint.MustParseAuthority(srv.Listener.Addr().String()),
				Trust: endpoint.Fingerprint{
					Type:        "certFingerprint",
					Fingerprint: primitive.Digest("sha256:" + hex.EncodeToString(leafSum[:])),
				},
				Name: "app",
			},
		},
		handle: output.ImageHandle{
			Ref:          "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
			ConfigDigest: primitive.Digest(configHash.String()),
		},
	}
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

	addr := srv.URL
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
			Artifacts: map[primitive.Identifier]record.Artifact{"image": {Digest: "sha256:abc"}},
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
	fx := newRegistryDeployFixture(t)

	state := newRuntime(t, "build", "deploy-prod")
	if err := state.Register("build", "", fx.handle); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method:    fx.method,
			Artifacts: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
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

	ca, dialer, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine:       fx.engine,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
		LaneID:       "test-lane",
		CA:           ca,
		Dialer:       dialer,
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
	// The deploy path flattens the pushed payload for cataloging, so the
	// layer must be a well-formed tar, not raw bytes.
	var layerBuf bytes.Buffer
	tw := tar.NewWriter(&layerBuf)
	if hdrErr := tw.WriteHeader(&tar.Header{Name: "artifact", Mode: 0o644, Size: int64(len("payload"))}); hdrErr != nil {
		t.Fatalf("layer tar header: %v", hdrErr)
	}
	if _, wErr := tw.Write([]byte("payload")); wErr != nil {
		t.Fatalf("layer tar content: %v", wErr)
	}
	if closeErr := tw.Close(); closeErr != nil {
		t.Fatalf("layer tar close: %v", closeErr)
	}
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err := mutate.AppendLayers(img, static.NewLayer(layerBuf.Bytes(), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	imgDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	configHash, err := img.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}
	lockJSON := []byte(`{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`)
	webTar, regionDiff, err := regtest.BuildLayeredImageTar("dist", map[string][]byte{"dist/package-lock.json": lockJSON})
	if err != nil {
		t.Fatalf("region producer tar: %v", err)
	}
	saved, err := regtest.LayoutTar(img)
	if err != nil {
		t.Fatalf("layout tar: %v", err)
	}
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/get") {
			w.Header().Set("Content-Type", "application/x-tar")
			body := saved
			if strings.Contains(r.URL.Path, "def456") {
				body = webTar
			}
			if _, wErr := w.Write(body); wErr != nil {
				t.Errorf("write save tar: %v", wErr)
			}
			return
		}
		t.Errorf("unexpected engine call: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))

	srv := httptest.NewTLSServer(ggcrregistry.New(ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	authority := srv.Listener.Addr().String()
	leafSum := sha256.Sum256(srv.Certificate().Raw)
	leafFP := primitive.Digest("sha256:" + hex.EncodeToString(leafSum[:]))

	state := newRuntime(t, "build", "web", "deploy-prod")
	if regErr := state.Register("build", "", output.ImageHandle{
		Ref:          "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
		ConfigDigest: primitive.Digest(configHash.String()),
	}); regErr != nil {
		t.Fatal(regErr)
	}
	if regErr := state.Register("web", "dist", output.FileHandle{
		Ref:         "localhost/test/web@sha256:def4560000000000000000000000000000000000000000000000000000000000",
		OutputID:    "dist",
		LayerDiffID: regionDiff,
	}); regErr != nil {
		t.Fatal(regErr)
	}
	distOut := primitive.Identifier("dist")

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployRegistry{
				Type: "registry",
				Target: lane.DeployRegistryTarget{
					Type:    "https",
					Address: endpoint.MustParseAuthority(authority),
					Trust:   endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: leafFP},
					Name:    "app",
				},
			},
			Artifacts: map[primitive.Identifier]lane.ArtifactRef{
				"image": {Step: "build"},
				"web":   {Step: "web", Output: &distOut},
			},
			Recording: lane.StateRecording{
				PreState:  lane.CaptureSet{Captures: []lane.Capture{}},
				PostState: lane.CaptureSet{Captures: []lane.Capture{}},
			},
		},
	}

	ca, dialer, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine:     eng,
		LaneDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Lane:       &lane.Lane{Steps: []lane.Step{{ID: "web", Outputs: []lane.FileOutput{{ID: "dist"}}}}},
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{
			"image": {Step: "build"},
			"web":   {Step: "web", Output: &distOut},
		},
		LaneID:    "test-lane",
		CA:        ca,
		Dialer:    dialer,
		CAVolume:  caPath,
		StepID:    "deploy-prod",
		StepPorts: ports,
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, execErr := d.Execute(context.Background(), step, state)
	if execErr != nil {
		t.Fatalf("Execute: %v", execErr)
	}

	op, ok := att.Sealed.ObservedPeers[endpoint.Authority(authority)]
	if !ok {
		t.Fatalf("push target %q missing from Sealed.ObservedPeers", authority)
	}
	tlsID, ok := op.Identity.(deploy.ObservedTLS)
	if !ok {
		t.Fatalf("push identity = %T, want deploy.ObservedTLS", op.Identity)
	}
	if tlsID.ServerCertFingerprint != leafFP {
		t.Errorf("push identity fingerprint = %s, want %s", tlsID.ServerCertFingerprint, leafFP)
	}
	if att.Sealed.Pushed == nil {
		t.Fatal("Sealed.Pushed is nil after a registry deploy")
	}
	if att.Sealed.Pushed.Digest.String() != imgDigest.String() {
		t.Errorf("Sealed.Pushed.Digest = %s, want the pushed manifest digest %s",
			att.Sealed.Pushed.Digest, imgDigest)
	}
	if string(att.Sealed.Pushed.Repository) != "app" {
		t.Errorf("Sealed.Pushed.Repository = %q, want \"app\"", att.Sealed.Pushed.Repository)
	}
	if att.Sealed.Pushed.Registry != endpoint.Authority(authority) {
		t.Errorf("Sealed.Pushed.Registry = %q, want %q", att.Sealed.Pushed.Registry, authority)
	}

	rt := srv.Client().Transport
	subjectRef, err := name.NewDigest(authority + "/app@" + imgDigest.String())
	if err != nil {
		t.Fatalf("subject digest ref: %v", err)
	}
	if _, headErr := remote.Head(subjectRef, remote.WithTransport(rt)); headErr != nil {
		t.Fatalf("pushed payload not at target: %v", headErr)
	}
	index, err := remote.Referrers(subjectRef, remote.WithTransport(rt))
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest: %v", err)
	}
	if len(manifest.Manifests) != 7 {
		t.Fatalf("referrers = %d, want 7 (3 statement bundles, 2 image SBOMs, 2 region SBOMs)", len(manifest.Manifests))
	}
	wantStatements := map[string]bool{"sealed": false, "engine-context": false, "informational": false}
	wantSBOM := map[string]int{"application/vnd.cyclonedx+json": 0, "application/spdx+json": 0}
	sbomArtifacts := map[string]bool{}
	for _, desc := range manifest.Manifests {
		if _, sbom := wantSBOM[string(desc.ArtifactType)]; sbom {
			wantSBOM[string(desc.ArtifactType)]++
			sref, srefErr := name.NewDigest(authority + "/app@" + desc.Digest.String())
			if srefErr != nil {
				t.Fatalf("sbom referrer digest ref: %v", srefErr)
			}
			simg, simgErr := remote.Image(sref, remote.WithTransport(rt))
			if simgErr != nil {
				t.Fatalf("fetch sbom referrer %s: %v", desc.Digest, simgErr)
			}
			smfst, smErr := simg.Manifest()
			if smErr != nil {
				t.Fatalf("sbom referrer manifest %s: %v", desc.Digest, smErr)
			}
			sbomArtifacts[smfst.Annotations["dev.strike.artifact"]] = true
			continue
		}
		dref, refErr := name.NewDigest(authority + "/app@" + desc.Digest.String())
		if refErr != nil {
			t.Fatalf("referrer digest ref: %v", refErr)
		}
		rimg, imgErr := remote.Image(dref, remote.WithTransport(rt))
		if imgErr != nil {
			t.Fatalf("fetch referrer %s: %v", desc.Digest, imgErr)
		}
		rimgMfst, mErr := rimg.Manifest()
		if mErr != nil {
			t.Fatalf("referrer manifest %s: %v", desc.Digest, mErr)
		}
		stmt := rimgMfst.Annotations["dev.strike.statement"]
		if _, known := wantStatements[stmt]; !known {
			t.Errorf("unexpected referrer: artifactType=%q statement=%q", desc.ArtifactType, stmt)
			continue
		}
		wantStatements[stmt] = true
	}
	for stmt, seen := range wantStatements {
		if !seen {
			t.Errorf("missing referrer for statement %q", stmt)
		}
	}
	for mt, count := range wantSBOM {
		if count != 2 {
			t.Errorf("SBOM referrers for %q = %d, want 2 (image + region)", mt, count)
		}
	}
	for _, want := range []string{"image", "web"} {
		if !sbomArtifacts[want] {
			t.Errorf("no SBOM referrer annotated dev.strike.artifact=%q", want)
		}
	}

	webArt, ok := att.Sealed.Artifacts["web"]
	if !ok {
		t.Fatal("Sealed.Artifacts missing region entry \"web\"")
	}
	if webArt.Digest != primitive.Digest(regionDiff) {
		t.Errorf("region digest = %s, want the layer diff_id %s", webArt.Digest, regionDiff)
	}
	if webArt.SBOM == nil {
		t.Fatal("region record carries no SBOM set")
	}
	if _, pErr := primitive.ParseDigest(webArt.SBOM.CycloneDX); pErr != nil {
		t.Errorf("region cyclonedx digest: %v", pErr)
	}
	if _, pErr := primitive.ParseDigest(webArt.SBOM.SPDX); pErr != nil {
		t.Errorf("region spdx digest: %v", pErr)
	}
	imgArt, ok := att.Sealed.Artifacts["image"]
	if !ok {
		t.Fatal("Sealed.Artifacts missing image entry \"image\"")
	}
	if imgArt.SBOM == nil {
		t.Error("image record carries no SBOM set")
	}
}

// TestDeployerExecuteRegistryRejectsUnverifiedExport proves the fail-closed
// export check: a deploy whose engine export does not match the produced config
// digest aborts before the transport is built, so nothing is pushed and nothing
// is signed (ADR-051 D4).
func TestDeployerExecuteRegistryRejectsUnverifiedExport(t *testing.T) {
	var layerBuf bytes.Buffer
	tw := tar.NewWriter(&layerBuf)
	if hdrErr := tw.WriteHeader(&tar.Header{Name: "artifact", Mode: 0o644, Size: int64(len("payload"))}); hdrErr != nil {
		t.Fatalf("layer tar header: %v", hdrErr)
	}
	if _, wErr := tw.Write([]byte("payload")); wErr != nil {
		t.Fatalf("layer tar content: %v", wErr)
	}
	if closeErr := tw.Close(); closeErr != nil {
		t.Fatalf("layer tar close: %v", closeErr)
	}
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err := mutate.AppendLayers(img, static.NewLayer(layerBuf.Bytes(), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	saved, err := regtest.LayoutTar(img)
	if err != nil {
		t.Fatalf("layout tar: %v", err)
	}
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/get") {
			w.Header().Set("Content-Type", "application/x-tar")
			if _, wErr := w.Write(saved); wErr != nil {
				t.Errorf("write save tar: %v", wErr)
			}
			return
		}
		t.Errorf("unexpected engine call: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))

	// A well-formed digest that is not this image's config digest.
	const wrongConfig = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	state := newRuntime(t, "build", "deploy-prod")
	if regErr := state.Register("build", "", output.ImageHandle{
		Ref:          "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
		ConfigDigest: wrongConfig,
	}); regErr != nil {
		t.Fatal(regErr)
	}

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployRegistry{
				Type: "registry",
				Target: lane.DeployRegistryTarget{
					Type:    "https",
					Address: endpoint.MustParseAuthority("localhost:5000"),
					Trust: endpoint.Fingerprint{
						Type:        "certFingerprint",
						Fingerprint: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
					},
					Name: "app",
				},
			},
			Artifacts: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
			Recording: lane.StateRecording{
				PreState:  lane.CaptureSet{Captures: []lane.Capture{}},
				PostState: lane.CaptureSet{Captures: []lane.Capture{}},
			},
		},
	}

	d := &deploy.Deployer{
		Engine:       eng,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
		LaneID:       "test-lane",
		StepID:       "deploy-prod",
	}
	deploy.SetProduceBundles(d, stubProduceBundles())
	att, execErr := d.Execute(context.Background(), step, state)
	if execErr == nil {
		t.Fatalf("Execute succeeded on an unverified export, got attestation %+v", att)
	}
	if !strings.Contains(execErr.Error(), "does not match the produced config digest") {
		t.Errorf("Execute error = %v, want it to report the config digest mismatch", execErr)
	}
}

func TestDeployerExecute_MissingArtifact(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
	state := newRuntime(t, "build", "deploy-prod") // no artifact outputs registered

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method:    deploy.DeployRegistryForTest(),
			Artifacts: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
			Recording: lane.StateRecording{},
		},
	}

	d := &deploy.Deployer{
		Engine:       eng,
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
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
			Method: deploy.DeployRegistryForTest(),
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
	fx := newRegistryDeployFixture(t)

	// Ping to populate identity
	if err := fx.engine.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	state := newRuntime(t, "build", "deploy-prod")
	if err := state.Register("build", "", fx.handle); err != nil {
		t.Fatal(err)
	}

	step := &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method:    fx.method,
			Artifacts: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
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

	ca, dialer, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	d := &deploy.Deployer{
		Engine: fx.engine, EngineID: fx.engine.Identity(),
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
		LaneID:       "test-lane",
		CA:           ca,
		Dialer:       dialer,
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
	if !strings.HasPrefix(tlsConn.ServerCertFingerprint.String(), "sha256:") {
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
// Execute edge cases.
// --------------------------------------------------------------------------.

func TestDeployerExecute_NotDeployStep(t *testing.T) {
	eng := newTLSTestEngine(t, containerMock(t, ""))
	state := newRuntime(t)
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
	state := newRuntime(t, "deploy-fail-pre")

	step := &lane.Step{
		ID: "deploy-fail-pre",
		Deploy: &lane.DeploySpec{
			Method: deploy.DeployRegistryForTest(),
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

	ca, dialer, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-fail-pre:version", "deploy-fail-pre")

	d := &deploy.Deployer{
		Engine:    eng,
		LaneID:    "test-lane",
		CA:        ca,
		Dialer:    dialer,
		CAVolume:  caPath,
		StepID:    "deploy-fail-pre",
		StepPorts: ports,
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
	fx := newRegistryDeployFixture(t)

	state := newRuntime(t, "build", "deploy-prod")
	if err := state.Register("build", "", fx.handle); err != nil {
		t.Fatal(err)
	}

	ca, dialer, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep(t, fx.method)
	d := &deploy.Deployer{
		Engine:       fx.engine,
		EngineID:     fx.engine.Identity(),
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
		LaneID:       "test-lane",
		CA:           ca,
		Dialer:       dialer,
		CAVolume:     caPath,
		StepID:       "deploy-prod",
		StepPorts:    ports,
	}
	var producedBundles [][]byte
	stub := stubProduceBundles()
	deploy.SetProduceBundles(d, func(ctx context.Context, eps lane.KeylessEndpoints, statements [][]byte) ([][]byte, error) {
		bundles, err := stub(ctx, eps, statements)
		producedBundles = bundles
		return bundles, err
	})

	_, err := d.Execute(context.Background(), step, state)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(producedBundles) != 3 {
		t.Fatalf("expected 3 signed bundles (sealed, engine-context, informational), got %d", len(producedBundles))
	}
	got := map[string][]byte{
		"sealed":         producedBundles[0],
		"engine-context": producedBundles[1],
		"informational":  producedBundles[2],
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
	fx := newRegistryDeployFixture(t)

	state := newRuntime(t, "build", "deploy-prod")
	if err := state.Register("build", "", fx.handle); err != nil {
		t.Fatal(err)
	}

	ca, dialer, caPath, ports := deployCapsuleFields(t,
		"capture:deploy-prod:version", "deploy-prod")

	step := deployStep(t, fx.method)
	d := &deploy.Deployer{
		Engine:       fx.engine,
		LaneDigest:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ArtifactRefs: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
		LaneID:       "test-lane",
		CA:           ca,
		Dialer:       dialer,
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

// deployStep returns a minimal deploy step for Rekor tests, on the deploy
// method the caller supplies.
func deployStep(t *testing.T, method lane.DeployMethod) *lane.Step {
	t.Helper()
	return &lane.Step{
		ID: "deploy-prod",
		Deploy: &lane.DeploySpec{
			Method:    method,
			Artifacts: map[primitive.Identifier]lane.ArtifactRef{"image": {Step: "build"}},
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
			Artifacts: map[primitive.Identifier]record.Artifact{},
			Peers:     map[primitive.Identifier][]lane.Peer{},
		},
		Informational: &deploy.Informational{
			Timestamp:       primitive.Timestamp(clock.Reproducible().Format(clock.RFC3339)),
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

// TestDeployExecute_StepTimeoutWithMediatedConnection drives a capture
// unit whose container never exits, holds a mediated connection open
// through that unit's capsule, and lets the step deadline expire. The
// deadline must surface as an error within a bound: capsule stop may
// not wait for the connection to close on its own, and the container
// the engine created must be removed.
func TestDeployExecute_StepTimeoutWithMediatedConnection(t *testing.T) {
	peerSNI := "capture-peer.example"
	fp, upAddr, upCleanup := deployTestUpstream(t, peerSNI)
	defer upCleanup()

	_, upPort, splitErr := net.SplitHostPort(upAddr)
	if splitErr != nil {
		t.Fatalf("SplitHostPort(%q): %v", upAddr, splitErr)
	}

	waiting := make(chan struct{}, 1)
	removed := make(chan string, 4)

	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/containers/create"):
			writeJSON(t, w, map[string]string{"Id": "capture-container"})

		case strings.HasSuffix(p, "/start"):
			w.WriteHeader(http.StatusNoContent)

		case strings.HasSuffix(p, "/wait"):
			select {
			case waiting <- struct{}{}:
			default:
			}
			<-r.Context().Done()

		case strings.HasSuffix(p, "/logs"):
			<-r.Context().Done()

		case r.Method == http.MethodDelete && strings.Contains(p, "/containers/"):
			removed <- p
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))

	captureKey := "capture:timeout-step:probe"
	ca, dialer, caVolume, ports := deployCapsuleFields(t, captureKey, "timeout-step")

	peer := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority(peerSNI + ":" + upPort),
		Trust:   endpoint.Fingerprint{Type: "certFingerprint", Fingerprint: fp},
	}

	// Required: true is load-bearing. With a non-required pre-state set,
	// Execute logs the capture failure and carries on into artifact
	// resolution, which dereferences the runtime state this test does not
	// build. Required makes the deadline the return value.
	step := &lane.Step{
		ID: "timeout-step",
		Deploy: &lane.DeploySpec{
			Method: deploy.DeployRegistryForTest(),
			Recording: lane.StateRecording{
				PreState: lane.CaptureSet{
					Required: true,
					Captures: []lane.Capture{{
						ID:      "probe",
						Image:   "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
						Command: []string{"cat", "/version"},
						Peers:   []lane.Peer{peer},
					}},
				},
			},
		},
	}

	d := &deploy.Deployer{
		Engine:     eng,
		LaneDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		LaneID:     "timeout-lane",
		CA:         ca,
		Dialer:     dialer,
		CAVolume:   caVolume,
		StepID:     "timeout-step",
		StepPorts:  ports,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*clock.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, execErr := d.Execute(ctx, step, nil)
		done <- execErr
	}()

	// Once the container's wait is in flight, open a mediated connection
	// through that unit's capsule and leave it open. This is the state in
	// which the deadline used to hang the lane inside capsule stop.
	startDeadline, startCancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer startCancel()
	select {
	case <-waiting:
	case <-startDeadline.Done():
		t.Fatal("the capture container's wait never reached the engine")
	}

	mediatorAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ports[captureKey].Mediator).String()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PublicCertPEM()) {
		t.Fatal("append CA cert to pool")
	}
	var clientDialer net.Dialer
	raw, dialErr := clientDialer.DialContext(ctx, "tcp", mediatorAddr)
	if dialErr != nil {
		t.Fatalf("dial capsule mediator at %s: %v", mediatorAddr, dialErr)
	}
	held := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: peerSNI,
		MinVersion: tls.VersionTLS13,
	})
	if hsErr := held.HandshakeContext(ctx); hsErr != nil {
		testutil.CloseLog(t, raw, "held raw conn")
		t.Fatalf("handshake through capsule mediator: %v", hsErr)
	}
	defer testutil.CloseLog(t, held, "held mediated conn")
	if _, wErr := held.Write([]byte("hold this open")); wErr != nil {
		t.Fatalf("write through mediator: %v", wErr)
	}

	execDeadline, execCancel := context.WithTimeout(context.Background(), 20*clock.Second)
	defer execCancel()
	select {
	case execErr := <-done:
		if execErr == nil {
			t.Fatal("expected Execute to fail on the step deadline")
		}
	case <-execDeadline.Done():
		t.Fatal("Execute did not return after the step deadline expired -- capsule stop blocked")
	}

	rmDeadline, rmCancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer rmCancel()
	select {
	case p := <-removed:
		if !strings.Contains(p, "capture-container") {
			t.Errorf("removed path = %q, want it to name capture-container", p)
		}
	case <-rmDeadline.Done():
		t.Fatal("the capture container was not removed after the deadline")
	}
}

// deployTestUpstream starts a TLS echo server with a self-signed cert
// valid for sni and returns its cert fingerprint and address. Kept local
// to this package: the mediator package has an equivalent for its own
// tests, and a little copying beats a shared test dependency across two
// packages.
func deployTestUpstream(t *testing.T, sni string) (fingerprint primitive.Digest, addr string, cleanup func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := clock.Wall()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    now.Add(-clock.Minute),
		NotAfter:     now.Add(clock.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create upstream cert: %v", err)
	}
	sum := sha256.Sum256(certDER)
	fingerprint = primitive.DigestFromHex(hex.EncodeToString(sum[:]))

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer testutil.CloseLog(t, conn, "deploy test upstream conn")
				if _, cpErr := io.Copy(conn, conn); cpErr != nil {
					return
				}
			}()
		}
	}()

	cleanup = func() {
		testutil.CloseLog(t, tlsLn, "deploy test upstream listener")
		wg.Wait()
	}
	return fingerprint, ln.Addr().String(), cleanup
}
