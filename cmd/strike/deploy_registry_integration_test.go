// This file runs a real lane through the real runContext against the local
// sigstore harness: a pack step assembles an image from a digest-pinned base,
// a deploy step pushes it to the harness registry over TLS with a declared
// trust anchor, and the test reads the pushed subject's referrers back from
// the registry side (ADR-051 D2/D3/D4, ADR-040 D3).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/front"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

const (
	// itestRegistryHost is the harness zot registry behind Caddy.
	itestRegistryHost = "registry.127.0.0.1.sslip.io:5443"
	// itestIssuer is the harness Keycloak realm; it must match the lane's
	// declared oidc.issuer, because the producer checks the token subject
	// against the declared identity before contacting Fulcio.
	itestIssuer = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
	// itestStatementAnnotation is the wire annotation key the deploy path
	// writes onto each statement-bundle referrer. The producing constant is
	// unexported; the test asserts the published wire value.
	itestStatementAnnotation = "dev.strike.statement"
	// itestSBOMReferrers is the number of SBOM referrers a registry deploy
	// attaches (CycloneDX and SPDX), and itestBundleReferrers the number of
	// projected statement bundles (sealed, engine-context, informational).
	itestSBOMReferrers   = 2
	itestBundleReferrers = 3
	// itestBundleLimit bounds the bundle document read back from the registry.
	itestBundleLimit = 8 << 20
)

// itestLaneTemplate is the fixture lane: a pack step with no files, so the
// assembled image is the digest-pinned base alone, and a registry deploy step
// that seals and pushes it. No step declares peers, so no step container and
// no capsule egress is involved -- the only network the lane itself opens is
// the control-plane push and the keyless chain, both anchored by declaration.
// Trust paths are absolute host paths, resolved into the template at run time.
const itestLaneTemplate = `name: registry-deploy-itest
id: registry-deploy-itest
secrets: {}
resolver:
  host: "127.0.0.1:8853"
  trust:
    type: caBundle
    path: __RESOLVER_CERT__
oidc:
  issuer: "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
  audience: "sigstore"
  identity: "tester@strike.localhost"
  trust:
    type: caBundle
    path: __CADDY_ROOT__
keyless:
  endpoints:
    fulcio:
      url: "https://fulcio.127.0.0.1.sslip.io:5555"
      trust:
        type: caBundle
        path: __CADDY_ROOT__
    rekor:
      url: "https://rekor.127.0.0.1.sslip.io:3003"
      trust:
        type: caBundle
        path: __CADDY_ROOT__
    tsa:
      url: "https://tsa.127.0.0.1.sslip.io:3004"
      trust:
        type: caBundle
        path: __CADDY_ROOT__
steps:
  - id: pack
    pack:
      base: cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b
      files: []
    args: []
    env: {}
    inputs: []
    secrets: []
    output: image
  - id: deploy
    deploy:
      method:
        type: registry
        target:
          host: registry.127.0.0.1.sslip.io:5443
          trust:
            type: caBundle
            path: __CADDY_ROOT__
          name: __REPO__
      artifacts:
        app:
          step: pack
      recording:
        preState:
          required: false
          captures: []
        postState:
          required: false
          captures: []
    args: []
    env: {}
    inputs: []
    secrets: []
    outputs: []
`

// TestRegistryDeployLive_Integration is the end-to-end sealing test. Bring-up:
//
//	cd test/sigstore-local && make up && make rekor-pubkey
//	go test ./cmd/strike -run TestRegistryDeployLive_Integration -v
//
// A harness whose containers exist but are stopped is restarted by the test
// itself, and the timestamp certificate chain is re-exported with it.
// Creating the harness stays an operator action.
//
// The harness is a prerequisite: the test runs by default and fails fast when
// it is down; set STRIKE_INTEGRATION=0 to skip. The repository name carries a
// per-run suffix, because the three statement bundles are freshly signed on
// every run and would otherwise accumulate as extra referrers of the same
// reproducible subject digest.
func TestRegistryDeployLive_Integration(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()

	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	caddyRoot := filepath.Join(harness, "pki", "caddy-root.crt")
	resolverCert := filepath.Join(harness, "pki", "resolver.crt")
	for _, f := range []string{caddyRoot, resolverCert} {
		if _, statErr := os.Stat(f); statErr != nil {
			t.Fatalf("harness material missing (run make up in test/sigstore-local): %v", statErr)
		}
	}
	t.Setenv("SIGSTORE_ID_TOKEN", testutil.MintIDToken(t, itestIssuer, caddyRoot))

	repo := fmt.Sprintf("strike-itest-%d", clock.Wall().UnixNano())
	lanePath := writeFixtureLane(t, caddyRoot, resolverCert, repo)

	rc := newLiveRunContext(ctx, t, engine, lanePath)

	// ADR-035: a lane run puts no payload on the controller filesystem. Point
	// the process temp directory at an empty directory of our own for the
	// duration of the run -- every host scratch mechanism resolves through it,
	// including one reached from a dependency rather than from strike. This
	// observes residue, not transient writes; the forbidigo rule is what rules
	// those out structurally.
	scratchWatch := t.TempDir()
	t.Setenv("TMPDIR", scratchWatch)

	if runErr := rc.runtime.Run(rc.runStep); runErr != nil {
		t.Fatalf("lane run: %v", runErr)
	}

	residue, readErr := os.ReadDir(scratchWatch)
	if readErr != nil {
		t.Fatalf("read controller temp directory: %v", readErr)
	}
	if len(residue) != 0 {
		names := make([]string, 0, len(residue))
		for _, e := range residue {
			names = append(names, e.Name())
		}
		t.Errorf("lane run left %d entries on the controller filesystem: %v", len(residue), names)
	}

	subject := pushedSubjectDigest(ctx, t, engine, rc)
	descs := referrerDescriptors(ctx, t, caddyRoot, repo, subject)
	assertReferrerSet(t, descs)
	assertBundleReadable(ctx, t, caddyRoot, repo, descs)
}

// writeFixtureLane renders the fixture lane into a temp directory and returns
// its path. The temp directory becomes the lane root, so nothing in the
// repository tree is written.
func writeFixtureLane(t *testing.T, caddyRoot, resolverCert, repo string) string {
	t.Helper()
	content := strings.NewReplacer(
		"__CADDY_ROOT__", caddyRoot,
		"__RESOLVER_CERT__", resolverCert,
		"__REPO__", repo,
	).Replace(itestLaneTemplate)
	path := filepath.Join(t.TempDir(), "lane.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture lane: %v", err)
	}
	return path
}

// newLiveRunContext assembles the same runContext cmdRun builds, using the
// error-returning constructors directly so a setup failure is a test failure
// instead of a process exit. Every resource is released through t.Cleanup in
// reverse construction order.
func newLiveRunContext(ctx context.Context, t *testing.T, engine container.Engine, lanePath string) *runContext {
	t.Helper()
	fp, p, laneDigest, idx, dag, err := validateLane(lanePath)
	if err != nil {
		t.Fatalf("validate fixture lane: %v", err)
	}

	probeCtx, probeCancel := context.WithTimeout(ctx, 5*clock.Second)
	resolverID, probeErr := transport.ProbeResolver(probeCtx, p.Resolver)
	probeCancel()
	if probeErr != nil {
		t.Fatalf("resolver probe failed (%v); set STRIKE_INTEGRATION=0 to skip integration tests", probeErr)
	}

	laneDir := filepath.Dir(fp.String())
	laneRoot, rootErr := os.OpenRoot(laneDir)
	if rootErr != nil {
		t.Fatalf("open lane root: %v", rootErr)
	}
	t.Cleanup(func() { testutil.CloseLog(t, laneRoot, "lane root") })

	ca, caErr := transport.New(p.ID)
	if caErr != nil {
		t.Fatalf("ephemeral CA: %v", caErr)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ca, "ephemeral CA") })

	ft, ftErr := front.New(ctx)
	if ftErr != nil {
		t.Fatalf("front: %v", ftErr)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ft, "front") })

	rc := &runContext{
		ctx:        ctx,
		engine:     engine,
		lane:       p,
		laneDigest: laneDigest,
		dag:        dag,
		stepIndex:  idx,
		regClient:  &registry.Client{Engine: engine},
		engineID:   engine.Identity(),
		ca:         ca,
		front:      ft,
		upstreamLook: capsule.UpstreamLookupFunc(func(ctx context.Context, host string) ([]netip.Addr, error) {
			return transport.LookupHost(ctx, p.Resolver, host)
		}),
		runtime:    lane.NewRuntime(dag),
		stepPorts:  allocateMediatedPorts(p),
		capsules:   map[primitive.Identifier]*capsule.NetworkCapsule{},
		laneRoot:   laneRoot,
		resolverID: resolverID,
		laneDir:    laneDir,
	}

	if capsErr := rc.buildCapsules(ctx); capsErr != nil {
		t.Fatalf("build capsules: %v", capsErr)
	}
	t.Cleanup(rc.stopCapsules)

	trust, trustErr := rc.planTrustVolumes(ctx, ca.PublicCertPEM())
	if trustErr != nil {
		t.Fatalf("plan trust volumes: %v", trustErr)
	}
	t.Cleanup(func() { rc.removeTrustVolumes(context.Background(), trust) })
	rc.trust = trust

	ft.Start(ctx)
	return rc
}

// pushedSubjectDigest recomputes the digest the deploy path pushed under: the
// engine re-encodes on export, so the pushed subject is the exported manifest
// digest, not the produced one. Both identities are sealed -- the exported one
// as Sealed.pushed, the produced one as the artifact record -- so the
// divergence is an attested record (ADR-051 D4/D6, ADR-046). This recomputes
// the exported digest from live engine data so the test can address it.
func pushedSubjectDigest(ctx context.Context, t *testing.T, engine container.Engine, rc *runContext) v1.Hash {
	t.Helper()
	handle, err := rc.runtime.Resolve(lane.OutputRef{Step: "pack", Output: ""})
	if err != nil {
		t.Fatalf("resolve pack output: %v", err)
	}
	produced, prodErr := output.ManifestDigest(handle)
	if prodErr != nil {
		t.Fatalf("produced digest: %v", prodErr)
	}
	tarBytes, saveErr := registry.SaveImage(ctx, engine, handle.ImageRef())
	if saveErr != nil {
		t.Fatalf("save packed image: %v", saveErr)
	}
	img, extractErr := registry.ImageFromOCITar(tarBytes)
	if extractErr != nil {
		t.Fatalf("read packed image: %v", extractErr)
	}
	exported, digestErr := img.Digest()
	if digestErr != nil {
		t.Fatalf("exported digest: %v", digestErr)
	}
	if exported.String() == produced.String() {
		t.Logf("exported digest equals produced digest %s", produced)
	} else {
		t.Logf("exported digest %s differs from produced digest %s", exported, produced)
	}
	return exported
}

// referrerDescriptors lists the referrers of the pushed subject from the
// registry side, unfiltered, so SBOM and statement-bundle referrers are seen
// in one index.
func referrerDescriptors(ctx context.Context, t *testing.T, caddyRoot, repo string, subject v1.Hash) []v1.Descriptor {
	t.Helper()
	ref, err := name.NewDigest(itestRegistryHost + "/" + repo + "@" + subject.String())
	if err != nil {
		t.Fatalf("subject reference: %v", err)
	}
	idx, refErr := remote.Referrers(ref,
		remote.WithTransport(itestTransport(t, caddyRoot)),
		remote.WithContext(ctx))
	if refErr != nil {
		t.Fatalf("list referrers of %s: %v", ref, refErr)
	}
	im, manifestErr := idx.IndexManifest()
	if manifestErr != nil {
		t.Fatalf("referrers index: %v", manifestErr)
	}
	return im.Manifests
}

// assertReferrerSet checks the published referrer set of a sealed registry
// deploy: two SBOMs and the three projected statement bundles.
func assertReferrerSet(t *testing.T, descs []v1.Descriptor) {
	t.Helper()
	if len(descs) != itestSBOMReferrers+itestBundleReferrers {
		t.Fatalf("got %d referrers, want %d", len(descs), itestSBOMReferrers+itestBundleReferrers)
	}
	statements := map[string]bool{}
	sbomTypes := map[string]bool{}
	for _, d := range descs {
		switch d.ArtifactType {
		case registry.SigstoreBundleMediaType:
			statements[d.Annotations[itestStatementAnnotation]] = true
		case "application/vnd.cyclonedx+json", "application/spdx+json":
			sbomTypes[d.ArtifactType] = true
		default:
			t.Errorf("unexpected referrer artifactType %q", d.ArtifactType)
		}
	}
	for _, want := range []string{"sealed", "engine-context", "informational"} {
		if !statements[want] {
			t.Errorf("no referrer annotated %s=%s", itestStatementAnnotation, want)
		}
	}
	if len(sbomTypes) != itestSBOMReferrers {
		t.Errorf("got %d distinct SBOM artifact types, want %d", len(sbomTypes), itestSBOMReferrers)
	}
}

// assertBundleReadable fetches one statement-bundle referrer and checks that
// its single layer is the bundle document itself. Cryptographic verification
// of the bundle is the verifier's job, not this test's.
func assertBundleReadable(ctx context.Context, t *testing.T, caddyRoot, repo string, descs []v1.Descriptor) {
	t.Helper()
	var bundleDigest string
	for _, d := range descs {
		if d.ArtifactType == registry.SigstoreBundleMediaType {
			bundleDigest = d.Digest.String()
			break
		}
	}
	if bundleDigest == "" {
		t.Fatal("no statement-bundle referrer to read back")
	}
	ref, err := name.NewDigest(itestRegistryHost + "/" + repo + "@" + bundleDigest)
	if err != nil {
		t.Fatalf("bundle reference: %v", err)
	}
	img, imgErr := remote.Image(ref,
		remote.WithTransport(itestTransport(t, caddyRoot)),
		remote.WithContext(ctx))
	if imgErr != nil {
		t.Fatalf("fetch bundle referrer: %v", imgErr)
	}
	layers, layerErr := img.Layers()
	if layerErr != nil {
		t.Fatalf("bundle layers: %v", layerErr)
	}
	if len(layers) != 1 {
		t.Fatalf("bundle referrer has %d layers, want 1", len(layers))
	}
	body, openErr := layers[0].Uncompressed()
	if openErr != nil {
		t.Fatalf("open bundle layer: %v", openErr)
	}
	defer testutil.CloseLog(t, body, "bundle layer")
	raw, readErr := io.ReadAll(io.LimitReader(body, itestBundleLimit))
	if readErr != nil {
		t.Fatalf("read bundle layer: %v", readErr)
	}
	var parsed map[string]any
	if jsonErr := json.Unmarshal(raw, &parsed); jsonErr != nil {
		t.Fatalf("bundle layer is not JSON: %v", jsonErr)
	}
	if _, ok := parsed["mediaType"]; !ok {
		t.Errorf("bundle document has no mediaType field")
	}
}

// itestTransport is the read-side counterpart of the deploy path's push
// transport: the caddy root is the only accepted anchor, and the scheme is
// pinned to https because go-containerregistry otherwise picks it from the
// registry name.
func itestTransport(t *testing.T, caddyRoot string) http.RoundTripper {
	t.Helper()
	cfg, err := transport.BuildTLSConfig(endpoint.CABundle{Type: "caBundle", Path: primitive.AbsPath(caddyRoot)})
	if err != nil {
		t.Fatalf("registry tls config: %v", err)
	}
	return itestHTTPSOnly{inner: &http.Transport{TLSClientConfig: cfg}}
}

// itestHTTPSOnly forces every request onto https before it reaches the dial
// layer.
type itestHTTPSOnly struct {
	inner http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (h itestHTTPSOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL.Scheme = "https"
	return h.inner.RoundTrip(r)
}
