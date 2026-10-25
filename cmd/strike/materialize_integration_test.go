// This file runs a real lane through the real runContext against the live
// engine and the local sigstore harness to prove the control-plane
// materialization of an external step image: a store that does not resolve
// the declared reference resolves it after the run, and a digest the
// registry does not hold fails the step before any container exists. The
// lane's deploy image arm is a pack step, so the run never depends on a
// container step's image output.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

const (
	// materializeFixture is the step image under test: a small public image
	// index no other test uses, pinned on 2026-10-25 (linux/amd64 and
	// linux/arm64, one layer of 4105617 compressed bytes). Should cgr.dev
	// stop serving this digest, the run fails at the fetch with a 404 and the
	// fixture is re-pinned by the operator.
	materializeFixture = "cgr.dev/chainguard/busybox@sha256:77beab05a39883aab436c4613b31c29aa68a686be4f4610c14f8f1da75d6bd6b"
	// materializeMissing names a digest the fixture's repository does not hold.
	materializeMissing = "cgr.dev/chainguard/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000001"
	// materializeEngineAPI is the libpod prefix the engine client uses.
	materializeEngineAPI = "http://d/v5.0.0/libpod"
)

// materializeLaneTemplate is the fixture lane. run executes the step image
// under test and hands its whole workdir, as a directory output, to pack;
// pack places it on the digest-pinned static base and is the image arm the
// registry deploy seals and pushes. run is forced: the deploy does not seal
// it, so without forceRun a cache entry from an earlier run of this lane
// would restore it and skip the create the test is about.
const materializeLaneTemplate = `name: materialize-itest
id: materialize-itest
secrets: {}
resolver:
  adn: resolver.127.0.0.1.sslip.io
  ip: 127.0.0.1
  port: 8853
  trust:
    cert: "__RESOLVER_CERT__"
oidc:
  issuer: "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
  audience: "sigstore"
  identity: "tester@strike.localhost"
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
steps:
  - id: run
    image: __IMAGE__
    args: ["true"]
    workdir: /work
    forceRun: true
    env: {}
    inputs: []
    secrets: []
    outputs:
      - id: tree
        type: directory
  - id: pack
    pack:
      base: cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b
      files:
        - from:
            step: run
            output: tree
          dest: /tree
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

// materializeEngineClient returns an HTTP client to the engine socket named
// by CONTAINER_HOST, for the two engine operations the Engine interface has
// no method for and these tests need: removing an image by name, and
// counting containers.
func materializeEngineClient(t *testing.T) *http.Client {
	t.Helper()
	host := os.Getenv("CONTAINER_HOST")
	sock, ok := strings.CutPrefix(host, "unix://")
	if !ok {
		t.Fatalf("CONTAINER_HOST = %q: the materialization tests need the unix socket", host)
	}
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return transport.DialUnixSocket(ctx, sock)
		},
	}}
}

// removeImageByName removes ref from the store; 404 means it was absent.
func removeImageByName(ctx context.Context, t *testing.T, client *http.Client, ref string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, materializeEngineAPI+"/images/"+url.PathEscape(ref), nil)
	if err != nil {
		t.Fatalf("remove request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("remove %s: %v", ref, err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("remove response: close: %v", cErr)
		}
	}()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("remove %s: status %d", ref, resp.StatusCode)
	}
}

// containerCount is the number of containers the engine holds, stopped ones
// included.
func containerCount(ctx context.Context, t *testing.T, client *http.Client) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, materializeEngineAPI+"/containers/json?all=true", nil)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list containers: %v", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Logf("list response: close: %v", cErr)
		}
	}()
	var list []json.RawMessage
	if decodeErr := json.NewDecoder(resp.Body).Decode(&list); decodeErr != nil {
		t.Fatalf("decode container list: %v", decodeErr)
	}
	return len(list)
}

// materializeHarness requires the harness and returns its two anchor files.
func materializeHarness(t *testing.T, engine container.Engine) (caddyRoot, resolverCert string) {
	t.Helper()
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	caddyRoot = filepath.Join(harness, "pki", "caddy-root.crt")
	resolverCert = filepath.Join(harness, "pki", "resolver.crt")
	for _, f := range []string{caddyRoot, resolverCert} {
		if _, statErr := os.Stat(f); statErr != nil {
			t.Fatalf("harness material missing (run make up in test/sigstore-local): %v", statErr)
		}
	}
	return caddyRoot, resolverCert
}

// writeMaterializeLane renders the fixture lane for image and repo into a
// temp directory and returns its path.
func writeMaterializeLane(t *testing.T, caddyRoot, resolverCert, image, repo string) string {
	t.Helper()
	caddy, caddyErr := testutil.CertificateFromPEMFile(caddyRoot)
	if caddyErr != nil {
		t.Fatalf("harness root anchor: %v", caddyErr)
	}
	resolver, resolverErr := testutil.CertificateFromPEMFile(resolverCert)
	if resolverErr != nil {
		t.Fatalf("harness resolver anchor: %v", resolverErr)
	}
	content := strings.NewReplacer(
		"__CADDY_ROOT__", caddy.Cert.String(),
		"__RESOLVER_CERT__", resolver.Cert.String(),
		"__IMAGE__", image,
		"__REPO__", repo,
	).Replace(materializeLaneTemplate)
	path := filepath.Join(t.TempDir(), "lane.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture lane: %v", err)
	}
	return path
}

// TestMaterializeStepImageLive_Integration removes the fixture from the store,
// runs the lane, and finds the declared reference resolvable afterwards; a
// second run with the store holding the image is green as well.
func TestMaterializeStepImageLive_Integration(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()
	caddyRoot, resolverCert := materializeHarness(t, engine)
	client := materializeEngineClient(t)
	t.Setenv("SIGSTORE_ID_TOKEN", testutil.MintIDToken(t, itestIssuer, caddyRoot))

	removeImageByName(ctx, t, client, materializeFixture)
	present, err := engine.ImageExists(ctx, materializeFixture)
	if err != nil {
		t.Fatalf("exists before: %v", err)
	}
	if present {
		t.Fatalf("%s still resolves after its removal: another name holds the record", materializeFixture)
	}

	repo := fmt.Sprintf("strike-itest-materialize-%d", clock.Wall().UnixNano())
	lanePath := writeMaterializeLane(t, caddyRoot, resolverCert, materializeFixture, repo)
	rc := newLiveRunContext(ctx, t, engine, lanePath)
	if runErr := rc.runtime.Run(rc.runStep); runErr != nil {
		t.Fatalf("lane run with the image absent: %v", runErr)
	}
	present, err = engine.ImageExists(ctx, materializeFixture)
	if err != nil {
		t.Fatalf("exists after: %v", err)
	}
	if !present {
		t.Fatalf("%s does not resolve after the run", materializeFixture)
	}

	again := newLiveRunContext(ctx, t, engine, lanePath)
	if runErr := again.runtime.Run(again.runStep); runErr != nil {
		t.Fatalf("lane run with the image present: %v", runErr)
	}
}

// TestMaterializeMissingDigestLive_Integration declares a digest the
// registry does not hold: the step fails at the fetch, before any container
// is created, and the lane never reaches its pack or deploy step.
func TestMaterializeMissingDigestLive_Integration(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()
	caddyRoot, resolverCert := materializeHarness(t, engine)
	client := materializeEngineClient(t)

	repo := fmt.Sprintf("strike-itest-materialize-missing-%d", clock.Wall().UnixNano())
	lanePath := writeMaterializeLane(t, caddyRoot, resolverCert, materializeMissing, repo)
	rc := newLiveRunContext(ctx, t, engine, lanePath)
	before := containerCount(ctx, t, client)
	runErr := rc.runtime.Run(rc.runStep)
	if runErr == nil {
		t.Fatal("lane run = nil error for a digest the registry does not hold")
	}
	if !strings.Contains(runErr.Error(), materializeMissing) || !strings.Contains(runErr.Error(), "fetch") {
		t.Errorf("error = %q, want it to name the reference and the fetch", runErr)
	}
	if after := containerCount(ctx, t, client); after != before {
		t.Errorf("containers before %d, after %d: a failed fetch must create none", before, after)
	}
}
