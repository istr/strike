// This file runs a real lane through the real runContext against the local
// sigstore harness: a pack step assembles an image from a digest-pinned base,
// a deploy step pushes it to the harness registry over TLS with a declared
// trust anchor, and the test reads the pushed subject's referrers back from
// the registry side (ADR-051 D2/D3/D4, ADR-040 D3).
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
	"github.com/istr/strike/internal/front"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
	"github.com/istr/strike/internal/verify"
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
	// projected statement bundles (sealed, engine-dependent, informational).
	itestSBOMReferrers   = 2
	itestBundleReferrers = 3
	// itestBundleLimit bounds the bundle document read back from the registry.
	itestBundleLimit = 8 << 20
	// itestFulcioURL is the harness Fulcio behind Caddy, the source of the
	// certificate chain in the published trusted root.
	itestFulcioURL = "https://fulcio.127.0.0.1.sslip.io:5555"
	// itestIdentity is the fixture lane's oidc identity, the harness builder's,
	// which UC1 names explicitly.
	itestIdentity = "https://forge.strike.localhost/istr/strike/bootstrap/lane.cue@refs/heads/main"
	// itestPublicPrefix is the harness repository prefix that admits anonymous
	// reads (test/sigstore-local/zot/config.json); the public copy of a
	// deployment keeps its repository names under it.
	itestPublicPrefix = "public/"
	// itestTrustRootRepo is the harness repository the trusted-root image is
	// published to. The name is fixed: the image is content-addressed and
	// written by digest without a tag, so a republication of the same
	// document is idempotent.
	itestTrustRootRepo = "strike-itest-trust-root"
)

// itestLaneTemplate is the fixture lane: a pack step with no files, so the
// assembled image is the digest-pinned base alone, and a registry deploy step
// that seals and pushes it. No step declares peers, so no step container and
// no capsule egress is involved -- the only network the lane itself opens is
// the control-plane base read, push and keyless chain, all anchored by
// declaration. The lane resolves through the public DoT resolver, which
// answers the harness names under sslip.io with the loopback; its anchor and
// the cgr.dev anchors are public roots, every other anchor is a harness
// certificate rendered into the template at run time.
const itestLaneTemplate = `name: registry-deploy-itest
id: registry-deploy-itest
secrets:
  builder-token: "env://SIGSTORE_ID_TOKEN"
  registry-token: "env://REGISTRY_ID_TOKEN"
resolver:
  adn: one.one.one.one
  ip: 1.1.1.1
  trust:
    cert: "__DOT_ROOT__"
oidc:
  issuer: "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
  audience: "sigstore"
  identity: "https://forge.strike.localhost/istr/strike/bootstrap/lane.cue@refs/heads/main"
  extensions:
    sourceRepositoryRef: "refs/heads/main"
  token: builder-token
  trust:
    cert: "__CADDY_ROOT__"
keyless:
  endpoints:
    fulcio:
      url: "https://fulcio.127.0.0.1.sslip.io:5555"
      trust:
        cert: "__CADDY_ROOT__"
    rekor:
      url: "https://rekor.127.0.0.1.sslip.io:3003"
      trust:
        cert: "__CADDY_ROOT__"
    tsa:
      url: "https://tsa.127.0.0.1.sslip.io:3004"
      trust:
        cert: "__CADDY_ROOT__"
registries:
  - registry:
      host: cgr.dev
      trust:
        cert: "__GTS_ROOT_R1__"
    storages:
      - host: 9236a389bd48b984df91adc1bc924620.r2.cloudflarestorage.com
        trust:
          cert: "__GTS_ROOT_R4__"
steps:
  - id: pack
    pack:
      base: cgr.dev/chainguard/static@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
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
            cert: "__CADDY_ROOT__"
          name: __REPO__
          credential:
            type: bearer
            token: registry-token
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
//	cd test/sigstore-local && make up
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
// reproducible subject digest. The test also publishes the running harness's
// trusted root as a digest-pinned single-layer image and reads it back.
func TestRegistryDeployLive_Integration(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()

	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	caddyRoot := filepath.Join(harness, "pki", "caddy-root.crt")
	if _, statErr := os.Stat(caddyRoot); statErr != nil {
		t.Fatalf("harness material missing (run make up in test/sigstore-local): %v", statErr)
	}
	t.Setenv("SIGSTORE_ID_TOKEN", testutil.MintIDToken(t, itestIssuer, testutil.HarnessBuilderClient, caddyRoot))
	registryToken := testutil.MintIDToken(t, itestIssuer, testutil.HarnessRegistryClient, caddyRoot)
	t.Setenv("REGISTRY_ID_TOKEN", registryToken)

	repo := fmt.Sprintf("strike-itest-%d", clock.Wall().UnixNano())
	lanePath := writeFixtureLane(t, caddyRoot, repo)

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

	// The harness repositories outside the public prefix are private
	// (ADR-058 D6): an anonymous read of the pushed subject is refused, and
	// every read-back presents the registry token the run was given.
	pushed, pushedErr := name.NewDigest(itestRegistryHost + "/" + repo + "@" + subject.String())
	if pushedErr != nil {
		t.Fatalf("subject reference: %v", pushedErr)
	}
	if _, anonErr := remote.Head(pushed, remote.WithTransport(itestTransport(t, caddyRoot)), remote.WithContext(ctx)); anonErr == nil {
		t.Errorf("anonymous read of %s succeeded; only repositories under %s admit anonymous reads", pushed, itestPublicPrefix)
	}
	auth := &authn.Bearer{Token: registryToken}

	descs := referrerDescriptors(ctx, t, caddyRoot, repo, subject, auth)
	assertReferrerSet(t, descs)
	assertBundleArtifactForm(ctx, t, caddyRoot, repo, subject, auth)
	assertBundleReadable(ctx, t, caddyRoot, repo, descs, auth)

	trustRoot, trustDoc := publishHarnessTrustRoot(ctx, t, harness, caddyRoot, auth)
	assertTrustRootReadable(ctx, t, caddyRoot, trustRoot, trustDoc, auth)
	anonymous := registry.SystemTransports{Roots: harnessRoots(t, caddyRoot)}
	assertVerifies(ctx, t, lanePath, pushed, trustRoot, anonymous)
	publicSubject, publicTrustRoot := copyToPublic(ctx, t, caddyRoot, repo, subject, descs, trustRoot, auth)
	assertVerifiesAnonymously(ctx, t, lanePath, publicSubject, publicTrustRoot, anonymous)
}

// harnessRoots is the pool of the harness's Caddy root, which every harness
// endpoint chains to. A test hands it to strike verify's anonymous reads,
// because the root is in no system store.
func harnessRoots(t *testing.T, caddyRoot string) *x509.CertPool {
	t.Helper()
	trust, err := testutil.CertificateFromPEMFile(caddyRoot)
	if err != nil {
		t.Fatalf("harness root anchor: %v", err)
	}
	cert, err := trust.Parse()
	if err != nil {
		t.Fatalf("harness root certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// assertVerifies runs strike verify in UC2 against the deployment (ADR-041
// amendment 2026-11-08). Under the registry token it reads the private
// repository pinned to the deploy target's anchor, and the published trust
// root on the same registry under the same token, and every layer verifies.
// Without the token it reads anonymously, the default, over TLS under the
// harness root, and the private registry refuses it. The harness registry
// serves every write at once, so the read does not wait.
func assertVerifies(ctx context.Context, t *testing.T, lanePath string, subject, trustRoot name.Digest, anonymous registry.SystemTransports) {
	t.Helper()
	source := "env://REGISTRY_ID_TOKEN"
	opts := verifyOptions{
		subjectRef:    subject.String(),
		laneFile:      lanePath,
		trustRootRef:  trustRoot.String(),
		registryToken: source,
	}
	logBuf := captureLog(t)
	if err := runVerify(ctx, io.Discard, opts, anonymous, failOnWait(t)); err != nil {
		t.Fatalf("verify under the registry token: %v\n%s", err, logBuf.String())
	}
	for _, layer := range []string{"sealed", "engine-dependent", "informational"} {
		if !strings.Contains(logBuf.String(), "OK    "+layer+"\n") {
			t.Errorf("want an OK verdict for %s, got: %q", layer, logBuf.String())
		}
	}
	withoutToken := opts
	withoutToken.registryToken = ""
	err := runVerify(ctx, io.Discard, withoutToken, anonymous, failOnWait(t))
	switch {
	case err == nil:
		t.Error("an anonymous verify read the private harness registry")
	case strings.Contains(err.Error(), "x509:"):
		t.Errorf("the anonymous verify failed on TLS, not on the private registry: %v", err)
	}
}

// copyToPublic copies the deployed subject, every referrer it carries and the
// published trust root by digest from their private harness repositories to
// the same names under the public prefix, under the registry token, and
// returns the public subject and trust-root references.
func copyToPublic(ctx context.Context, t *testing.T, caddyRoot, repo string, subject v1.Hash, referrers []v1.Descriptor, trustRoot name.Digest, auth authn.Authenticator) (publicSubject, publicTrustRoot name.Digest) {
	t.Helper()
	opts := []remote.Option{remote.WithTransport(itestTransport(t, caddyRoot)), remote.WithAuth(auth), remote.WithContext(ctx)}
	copyImage := func(fromRepo, digest string) name.Digest {
		from, err := name.NewDigest(itestRegistryHost + "/" + fromRepo + "@" + digest)
		if err != nil {
			t.Fatalf("source reference: %v", err)
		}
		to, err := name.NewDigest(itestRegistryHost + "/" + itestPublicPrefix + fromRepo + "@" + digest)
		if err != nil {
			t.Fatalf("public reference: %v", err)
		}
		img, err := remote.Image(from, opts...)
		if err != nil {
			t.Fatalf("read %s: %v", from, err)
		}
		if writeErr := remote.Write(to, img, append(opts, remote.WithReferrersTagFallback(false))...); writeErr != nil {
			t.Fatalf("copy %s to %s: %v", from, to, writeErr)
		}
		return to
	}
	publicSubject = copyImage(repo, subject.String())
	for _, d := range referrers {
		copyImage(repo, d.Digest.String())
	}
	return publicSubject, copyImage(trustRoot.Context().RepositoryStr(), trustRoot.DigestStr())
}

// assertVerifiesAnonymously runs strike verify with no registry token
// against the public copy of the deployment (ADR-041 amendment 2026-11-08):
// in UC2 with the fixture lane as the policy, and in UC1 with the fixture
// lane's identity and issuer given explicitly. Both read anonymously over
// TLS under the harness root, and every layer verifies without a wait.
func assertVerifiesAnonymously(ctx context.Context, t *testing.T, lanePath string, subject, trustRoot name.Digest, anonymous registry.SystemTransports) {
	t.Helper()
	cases := []struct {
		name string
		opts verifyOptions
	}{
		{name: "UC2", opts: verifyOptions{subjectRef: subject.String(), laneFile: lanePath, trustRootRef: trustRoot.String()}},
		{name: "UC1", opts: verifyOptions{subjectRef: subject.String(), identity: itestIdentity, issuer: itestIssuer, trustRootRef: trustRoot.String()}},
	}
	for _, c := range cases {
		logBuf := captureLog(t)
		if err := runVerify(ctx, io.Discard, c.opts, anonymous, failOnWait(t)); err != nil {
			t.Fatalf("%s: anonymous verify of the public copy: %v\n%s", c.name, err, logBuf.String())
		}
		for _, layer := range []string{"sealed", "engine-dependent", "informational"} {
			if !strings.Contains(logBuf.String(), "OK    "+layer+"\n") {
				t.Errorf("%s: want an OK verdict for %s, got: %q", c.name, layer, logBuf.String())
			}
		}
	}
}

// writeFixtureLane renders the fixture lane into a temp directory and returns
// its path. The harness anchor is read from the harness PKI file, because a
// lane that dials the harness has to trust what the harness presents; the
// temp directory becomes the lane root, so nothing in the repository tree is
// written.
func writeFixtureLane(t *testing.T, caddyRoot, repo string) string {
	t.Helper()
	caddy, caddyErr := testutil.CertificateFromPEMFile(caddyRoot)
	if caddyErr != nil {
		t.Fatalf("harness root anchor: %v", caddyErr)
	}
	content := strings.NewReplacer(
		"__CADDY_ROOT__", caddy.Cert.String(),
		"__DOT_ROOT__", testutil.SSLComRootECCB64,
		"__GTS_ROOT_R1__", testutil.GTSRootR1B64,
		"__GTS_ROOT_R4__", testutil.GTSRootR4B64,
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

	dialer, dialerErr := transport.NewDialer(p.Resolver)
	if dialerErr != nil {
		t.Fatalf("transport.NewDialer: %v", dialerErr)
	}

	probeCtx, probeCancel := context.WithTimeout(ctx, 5*clock.Second)
	resolverID, probeErr := dialer.Probe(probeCtx)
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

	registryTokens, tokErr := deploy.ReadRegistryTokens(p, laneRoot)
	if tokErr != nil {
		t.Fatalf("read registry tokens: %v", tokErr)
	}

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
		ctx:            ctx,
		engine:         engine,
		lane:           p,
		laneDigest:     laneDigest,
		dag:            dag,
		stepIndex:      idx,
		regClient:      &registry.Client{Engine: engine},
		engineID:       engine.Identity(),
		ca:             ca,
		front:          ft,
		dialer:         dialer,
		reads:          registry.NewReads(dialer, p, registryTokens),
		registryTokens: registryTokens,
		runtime:        lane.NewRuntime(dag),
		capsules:       map[primitive.Identifier]*capsule.NetworkCapsule{},
		laneRoot:       laneRoot,
		resolverID:     resolverID,
		laneDir:        laneDir,
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
func referrerDescriptors(ctx context.Context, t *testing.T, caddyRoot, repo string, subject v1.Hash, auth authn.Authenticator) []v1.Descriptor {
	t.Helper()
	ref, err := name.NewDigest(itestRegistryHost + "/" + repo + "@" + subject.String())
	if err != nil {
		t.Fatalf("subject reference: %v", err)
	}
	idx, refErr := remote.Referrers(ref,
		remote.WithTransport(itestTransport(t, caddyRoot)),
		remote.WithAuth(auth),
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

// assertBundleArtifactForm lists the pushed subject's referrers the way a
// verifier does -- filtered by the bundle artifact type, with the referrers
// tag fallback refused -- and checks that every listed bundle referrer carries
// the OCI 1.1 artifact form: the manifest artifactType and the OCI empty
// config.
func assertBundleArtifactForm(ctx context.Context, t *testing.T, caddyRoot, repo string, subject v1.Hash, auth authn.Authenticator) {
	t.Helper()
	rt := itestTransport(t, caddyRoot)
	ref, err := name.NewDigest(itestRegistryHost + "/" + repo + "@" + subject.String())
	if err != nil {
		t.Fatalf("subject reference: %v", err)
	}
	idx, refErr := remote.Referrers(ref,
		remote.WithFilter("artifactType", registry.SigstoreBundleMediaType),
		remote.WithReferrersTagFallback(false),
		remote.WithTransport(rt),
		remote.WithAuth(auth),
		remote.WithContext(ctx))
	if refErr != nil {
		t.Fatalf("list bundle referrers of %s: %v", ref, refErr)
	}
	im, manifestErr := idx.IndexManifest()
	if manifestErr != nil {
		t.Fatalf("bundle referrers index: %v", manifestErr)
	}
	if len(im.Manifests) != itestBundleReferrers {
		t.Fatalf("filtered listing has %d bundle referrers, want %d", len(im.Manifests), itestBundleReferrers)
	}
	for _, d := range im.Manifests {
		mref, mrefErr := name.NewDigest(itestRegistryHost + "/" + repo + "@" + d.Digest.String())
		if mrefErr != nil {
			t.Fatalf("referrer reference: %v", mrefErr)
		}
		img, imgErr := remote.Image(mref, remote.WithTransport(rt), remote.WithAuth(auth), remote.WithContext(ctx))
		if imgErr != nil {
			t.Fatalf("fetch referrer %s: %v", d.Digest, imgErr)
		}
		man, manErr := img.Manifest()
		if manErr != nil {
			t.Fatalf("referrer manifest %s: %v", d.Digest, manErr)
		}
		if man.ArtifactType != registry.SigstoreBundleMediaType {
			t.Errorf("referrer %s artifactType = %q, want %q", d.Digest, man.ArtifactType, registry.SigstoreBundleMediaType)
		}
		if man.Config.MediaType != types.OCIEmptyJSON {
			t.Errorf("referrer %s config media type = %q, want %q", d.Digest, man.Config.MediaType, types.OCIEmptyJSON)
		}
	}
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
	for _, want := range []string{"sealed", "engine-dependent", "informational"} {
		if !statements[want] {
			t.Errorf("no referrer annotated %s=%s", itestStatementAnnotation, want)
		}
	}
	if len(sbomTypes) != itestSBOMReferrers {
		t.Errorf("got %d distinct SBOM artifact types, want %d", len(sbomTypes), itestSBOMReferrers)
	}
}

// assertBundleReadable fetches the sealed statement-bundle referrer and checks
// that its single layer is the bundle document itself, and that the sealed
// statement records the registry target as an observed peer together with the
// DoT answers the push dialed from. Cryptographic verification of the bundle
// is the verifier's job, not this test's.
func assertBundleReadable(ctx context.Context, t *testing.T, caddyRoot, repo string, descs []v1.Descriptor, auth authn.Authenticator) {
	t.Helper()
	var bundleDigest string
	for _, d := range descs {
		if d.ArtifactType == registry.SigstoreBundleMediaType && d.Annotations[itestStatementAnnotation] == "sealed" {
			bundleDigest = d.Digest.String()
			break
		}
	}
	if bundleDigest == "" {
		t.Fatal("no sealed statement-bundle referrer to read back")
	}
	ref, err := name.NewDigest(itestRegistryHost + "/" + repo + "@" + bundleDigest)
	if err != nil {
		t.Fatalf("bundle reference: %v", err)
	}
	img, imgErr := remote.Image(ref,
		remote.WithTransport(itestTransport(t, caddyRoot)),
		remote.WithAuth(auth),
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
	var parsed struct {
		MediaType *string `json:"mediaType"`
		Envelope  struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if jsonErr := json.Unmarshal(raw, &parsed); jsonErr != nil {
		t.Fatalf("bundle layer is not JSON: %v", jsonErr)
	}
	if parsed.MediaType == nil {
		t.Errorf("bundle document has no mediaType field")
	}
	var statement struct {
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters struct {
					ObservedPeers map[string]struct {
						Resolved []string `json:"resolved"`
					} `json:"observedPeers"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if jsonErr := json.Unmarshal(parsed.Envelope.Payload, &statement); jsonErr != nil {
		t.Fatalf("sealed statement is not JSON: %v", jsonErr)
	}
	peer, ok := statement.Predicate.BuildDefinition.ExternalParameters.ObservedPeers[itestRegistryHost]
	if !ok {
		t.Fatalf("sealed observedPeers has no entry for the registry target %s", itestRegistryHost)
	}
	if len(peer.Resolved) == 0 {
		t.Errorf("sealed observedPeers[%s].resolved is empty; the push resolved the target through the lane resolver", itestRegistryHost)
	}
}

// publishHarnessTrustRoot assembles the running harness's trusted root and
// pushes it by digest, without a tag, under auth into the harness registry,
// as the single-layer image a trust-root reference names. The harness
// registry starts empty and the timestamp authority mints a fresh chain on
// every harness start, so the image is published per run. It returns the
// digest-pinned reference and the document it carries.
func publishHarnessTrustRoot(ctx context.Context, t *testing.T, harness, caddyRoot string, auth authn.Authenticator) (name.Digest, []byte) {
	t.Helper()
	dialer, err := testutil.HarnessDialer(harness)
	if err != nil {
		t.Fatalf("harness dialer: %v", err)
	}
	trust, err := testutil.CertificateFromPEMFile(caddyRoot)
	if err != nil {
		t.Fatalf("harness root anchor: %v", err)
	}
	fulcio := endpoint.HTTPS{Address: endpoint.MustParseURL(itestFulcioURL), Trust: trust}
	client, err := deploy.HTTPClientFor(fulcio, dialer)
	if err != nil {
		t.Fatalf("fulcio client: %v", err)
	}
	doc, err := testutil.HarnessTrustedRoot(ctx, client, fulcio.Address.URL(), harness)
	if err != nil {
		t.Fatalf("harness trusted root: %v", err)
	}
	img, err := mutate.AppendLayers(mutate.MediaType(empty.Image, types.OCIManifestSchema1), static.NewLayer(doc, types.OCILayer))
	if err != nil {
		t.Fatalf("trusted-root image: %v", err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("trusted-root image digest: %v", err)
	}
	ref, err := name.NewDigest(itestRegistryHost + "/" + itestTrustRootRepo + "@" + digest.String())
	if err != nil {
		t.Fatalf("trusted-root reference: %v", err)
	}
	if writeErr := remote.Write(ref, img,
		remote.WithTransport(itestTransport(t, caddyRoot)),
		remote.WithAuth(auth),
		remote.WithContext(ctx)); writeErr != nil {
		t.Fatalf("push trusted-root image: %v", writeErr)
	}
	return ref, doc
}

// assertTrustRootReadable reads the published trusted-root image back under
// auth and checks that its sole layer is the assembled document, byte for
// byte, and parses as a trusted root.
func assertTrustRootReadable(ctx context.Context, t *testing.T, caddyRoot string, ref name.Digest, want []byte, auth authn.Authenticator) {
	t.Helper()
	img, err := remote.Image(ref,
		remote.WithTransport(itestTransport(t, caddyRoot)),
		remote.WithAuth(auth),
		remote.WithContext(ctx))
	if err != nil {
		t.Fatalf("fetch trusted-root image: %v", err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("trusted-root layers: %v", err)
	}
	if len(layers) != 1 {
		t.Fatalf("trusted-root image has %d layers, want 1", len(layers))
	}
	body, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatalf("open trusted-root layer: %v", err)
	}
	defer testutil.CloseLog(t, body, "trusted-root layer")
	got, err := io.ReadAll(io.LimitReader(body, itestBundleLimit))
	if err != nil {
		t.Fatalf("read trusted-root layer: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("trusted-root layer differs from the published document")
	}
	if _, parseErr := verify.ParseTrustedRoot(got); parseErr != nil {
		t.Errorf("published trusted root does not parse: %v", parseErr)
	}
}

// itestTransport is the read-side counterpart of the deploy path's push
// transport: the caddy root is the only accepted anchor, and the scheme is
// pinned to https because go-containerregistry otherwise picks it from the
// registry name.
func itestTransport(t *testing.T, caddyRoot string) http.RoundTripper {
	t.Helper()
	trust, trustErr := testutil.CertificateFromPEMFile(caddyRoot)
	if trustErr != nil {
		t.Fatalf("registry tls anchor: %v", trustErr)
	}
	cfg, err := transport.BuildTLSConfig(trust)
	if err != nil {
		t.Fatalf("registry tls config: %v", err)
	}
	return transport.HTTPSOnly(&http.Transport{TLSClientConfig: cfg})
}
