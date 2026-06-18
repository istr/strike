package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/verify"
)

// The golden bundles in internal/verify/testdata/golden verify against the
// golden trusted_root.json under this identity and issuer (see the verify
// package's differential test). The trusted time is sealed in each bundle, so
// the chain verifies offline regardless of the wall clock.
const (
	goldenIdentity = "tester@strike.localhost"
	goldenIssuer   = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
)

func goldenFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(
		filepath.Join("..", "..", "internal", "verify", "testdata", "golden", name)))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return b
}

// goldenSubjectHex decodes the bundle's DSSE payload (the in-toto statement)
// and returns the first subject's sha256, the digest the producer signed over.
func goldenSubjectHex(t *testing.T, bundleJSON []byte) string {
	t.Helper()
	var b struct {
		DSSEEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatalf("decode dsse payload: %v", err)
	}
	var s struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatalf("decode statement: %v", err)
	}
	if len(s.Subject) == 0 || s.Subject[0].Digest["sha256"] == "" {
		t.Fatalf("golden statement carries no subject sha256")
	}
	return s.Subject[0].Digest["sha256"]
}

// goldenTrustRootRef publishes the golden trusted_root.json as a single-layer
// OCI image to host and returns its digest-pinned reference -- the
// --trust-root-ref override lever. The verify path reads no host-local file; the
// override is fetched from the registry by digest, exactly like a lane-declared
// trustRootRef.
func goldenTrustRootRef(t *testing.T, host string) string {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err := mutate.AppendLayers(img, static.NewLayer(goldenFile(t, "trusted_root.json"), types.OCILayer))
	if err != nil {
		t.Fatalf("append trust-root layer: %v", err)
	}
	nameRef, err := name.ParseReference(host + "/trust:v1")
	if err != nil {
		t.Fatalf("parse trust-root ref: %v", err)
	}
	if writeErr := remote.Write(nameRef, img); writeErr != nil {
		t.Fatalf("push trust root: %v", writeErr)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("trust-root digest: %v", err)
	}
	return host + "/trust@" + digest.String()
}

// localRegistry starts an in-memory OCI registry with referrers support and
// returns its localhost:<port> host (ggcr dials plain HTTP for localhost).
func localRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return "localhost:" + u.Port()
}

// attachGolden attaches bundle as a sealed-statement referrer of the synthetic
// subject digest in host/app. The subject manifest itself is never pushed: the
// referrers API keys on the subject digest, not on the subject's existence.
func attachGolden(t *testing.T, host, subjectHex string, bundle []byte) {
	t.Helper()
	h, err := v1.NewHash("sha256:" + subjectHex)
	if err != nil {
		t.Fatalf("subject hash: %v", err)
	}
	subject := v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 2, Digest: h}
	if err := registry.AttachStatementBundles(context.Background(), host+"/app:v1", subject,
		[]registry.StatementBundle{{Statement: "sealed", Bundle: bundle}}); err != nil {
		t.Fatalf("AttachStatementBundles: %v", err)
	}
}

// attachGoldenLayers attaches the named golden layers (e.g. "sealed",
// "engine-context", "informational") as co-attached referrers of the subject
// digest, each carrying its golden bundle. The three goldens share one subject
// (the 3a synthetic attestation), so any subset binds to the same digest.
func attachGoldenLayers(t *testing.T, host, subjectHex string, layers ...string) {
	t.Helper()
	h, err := v1.NewHash("sha256:" + subjectHex)
	if err != nil {
		t.Fatalf("subject hash: %v", err)
	}
	subject := v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 2, Digest: h}
	sb := make([]registry.StatementBundle, 0, len(layers))
	for _, layer := range layers {
		sb = append(sb, registry.StatementBundle{Statement: layer, Bundle: goldenFile(t, layer+".sigstore.json")})
	}
	if err := registry.AttachStatementBundles(context.Background(), host+"/app:v1", subject, sb); err != nil {
		t.Fatalf("AttachStatementBundles: %v", err)
	}
}

// captureLog redirects the default logger to a buffer for the duration of the
// test and returns it, so the non-gating "absent" diagnostics can be asserted.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// pushSubject pushes a minimal OCI image to ref and returns its descriptor,
// mirroring internal/registry's referrer_test helper.
func pushSubject(t *testing.T, ref string) v1.Descriptor {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err := mutate.AppendLayers(img, static.NewLayer([]byte("subject"), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	nameRef, err := name.ParseReference(ref)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if writeErr := remote.Write(nameRef, img); writeErr != nil {
		t.Fatalf("push subject: %v", writeErr)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	size, err := img.Size()
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	mt, err := img.MediaType()
	if err != nil {
		t.Fatalf("media type: %v", err)
	}
	return v1.Descriptor{MediaType: mt, Digest: digest, Size: size}
}

// TestRunVerifyHappyPathUC1 runs the full read -> resolve -> verify ->
// subject-match -> predicate chain with no harness: the three golden bundles,
// the golden trusted root via --trust-root, and an in-memory registry. UC1 has
// no policy lane, so the sealed laneDigest is checked present but not matched.
// This is the round-trip the override lever exists to enable.
func TestRunVerifyHappyPathUC1(t *testing.T) {
	subjectHex := goldenSubjectHex(t, goldenFile(t, "sealed.sigstore.json"))

	host := localRegistry(t)
	attachGoldenLayers(t, host, subjectHex, "sealed", "engine-context", "informational")

	var out bytes.Buffer
	opts := verifyOptions{
		subjectRef:   host + "/app@sha256:" + subjectHex,
		identity:     goldenIdentity,
		issuer:       goldenIssuer,
		trustRootRef: goldenTrustRootRef(t, host),
	}
	if err := runVerify(context.Background(), &out, opts); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
	// Each verified in-toto statement, not arbitrary text, reaches stdout, one
	// per line; the first must name the requested artifact.
	first := bytes.SplitN(out.Bytes(), []byte("\n"), 2)[0]
	var st struct {
		Type    string `json:"_type"`
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(first, &st); err != nil {
		t.Fatalf("output is not a JSON statement: %v (%q)", err, out.String())
	}
	if st.Type == "" || len(st.Subject) == 0 || st.Subject[0].Digest["sha256"] != subjectHex {
		t.Fatalf("output statement subject = %+v, want sha256 %s", st.Subject, subjectHex)
	}
}

// TestRunVerifySubjectMismatch attaches the validly signed bundle as a referrer
// of a different subject digest: the keyless chain still passes, so only the
// in-statement subject check stands between a hostile registry and a confused
// artifact. It must bite.
func TestRunVerifySubjectMismatch(t *testing.T) {
	bundle := goldenFile(t, "sealed.sigstore.json")
	subjectHex := goldenSubjectHex(t, bundle)
	other := strings.Repeat("0", 63) + "f"
	if other == subjectHex {
		t.Fatal("test setup: substitute digest collides with the real subject")
	}

	// Positive control: under this exact policy the bundle's keyless chain
	// verifies and its true subject is subjectHex. So when runVerify rejects the
	// bundle below, the only thing that can have bitten is the subject-digest
	// check -- not an incidental chain failure.
	tm, err := verify.ParseTrustedRoot(goldenFile(t, "trusted_root.json"))
	if err != nil {
		t.Fatalf("parse golden trusted root: %v", err)
	}
	stmt, err := verify.New(tm, goldenIdentity, goldenIssuer).Verify(bundle)
	if err != nil {
		t.Fatalf("golden bundle must verify under the golden policy: %v", err)
	}
	if !subjectMatches(stmt, subjectHex) {
		t.Fatalf("golden bundle subject is not %s", subjectHex)
	}

	host := localRegistry(t)
	attachGolden(t, host, other, bundle)

	var out bytes.Buffer
	opts := verifyOptions{
		subjectRef:   host + "/app@sha256:" + other,
		identity:     goldenIdentity,
		issuer:       goldenIssuer,
		trustRootRef: goldenTrustRootRef(t, host),
	}
	if err := runVerify(context.Background(), &out, opts); err == nil {
		t.Fatal("runVerify accepted a bundle whose subject is not the requested artifact")
	}
	if out.Len() != 0 {
		t.Fatalf("a mismatched statement must not be written; got %q", out.String())
	}
}

func TestRunVerifyModeValidation(t *testing.T) {
	ref := "example.com/app@sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name string
		opts verifyOptions
	}{
		{"identity with lane", verifyOptions{subjectRef: ref, identity: goldenIdentity, laneFile: "lane.yaml"}},
		{"issuer with lane", verifyOptions{subjectRef: ref, issuer: goldenIssuer, laneFile: "lane.yaml"}},
		{"neither mode", verifyOptions{subjectRef: ref}},
		{"uc1 missing issuer", verifyOptions{subjectRef: ref, identity: goldenIdentity}},
		{"uc1 missing identity", verifyOptions{subjectRef: ref, issuer: goldenIssuer}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := runVerify(context.Background(), io.Discard, tt.opts); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
}

// TestRunVerifyNoTrustRoot: UC1 with no --trust-root and no lane has no anchor;
// ResolveTrustedMaterial's sentinel must surface.
func TestRunVerifyNoTrustRoot(t *testing.T) {
	opts := verifyOptions{
		subjectRef: "example.com/app@sha256:" + strings.Repeat("0", 64),
		identity:   goldenIdentity,
		issuer:     goldenIssuer,
	}
	if err := runVerify(context.Background(), io.Discard, opts); !errors.Is(err, verify.ErrNoTrustRoot) {
		t.Fatalf("err = %v, want ErrNoTrustRoot", err)
	}
}

// TestRunVerifyNoBundles: a subject with no referrers is not verifiable.
func TestRunVerifyNoBundles(t *testing.T) {
	host := localRegistry(t)
	subject := pushSubject(t, host+"/app:v1")
	opts := verifyOptions{
		subjectRef:   host + "/app@" + subject.Digest.String(),
		identity:     goldenIdentity,
		issuer:       goldenIssuer,
		trustRootRef: goldenTrustRootRef(t, host),
	}
	err := runVerify(context.Background(), io.Discard, opts)
	if err == nil || !strings.Contains(err.Error(), "no attestation bundles") {
		t.Fatalf("err = %v, want a no-bundles error", err)
	}
}

func TestSubjectMatches(t *testing.T) {
	const want = "0000000000000000000000000000000000000000000000000000000000000001"
	tests := []struct {
		name      string
		statement string
		wantMatch bool
	}{
		{"match", `{"subject":[{"digest":{"sha256":"` + want + `"}}]}`, true},
		{"second of two", `{"subject":[{"digest":{"sha256":"dead"}},{"digest":{"sha256":"` + want + `"}}]}`, true},
		{"wrong value", `{"subject":[{"digest":{"sha256":"dead"}}]}`, false},
		{"absent sha256", `{"subject":[{"digest":{"sha512":"` + want + `"}}]}`, false},
		{"empty subject", `{"subject":[]}`, false},
		{"malformed json", `{"subject":`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subjectMatches([]byte(tt.statement), want); got != tt.wantMatch {
				t.Fatalf("subjectMatches = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// TestValidatePredicate covers the per-layer predicate checks: predicateType
// must match the layer, and the sealed layer must carry a laneDigest (always
// present, and equal to the policy lane's digest in UC2; unconstrained in UC1).
func TestValidatePredicate(t *testing.T) {
	dgA := "sha256:" + strings.Repeat("a", 64)
	dgB := "sha256:" + strings.Repeat("b", 64)
	sealedStmt := func(dg string) []byte {
		return []byte(`{"predicateType":"` + sealedPredicateType +
			`","predicate":{"buildDefinition":{"externalParameters":{"laneDigest":"` + dg + `"}}}}`)
	}
	typed := func(pt string) []byte { return []byte(`{"predicateType":"` + pt + `"}`) }
	tests := []struct {
		name       string
		layer      string
		laneDigest string
		statement  []byte
		wantErr    bool
	}{
		{"sealed UC2 match", "sealed", dgA, sealedStmt(dgA), false},
		{"sealed UC2 mismatch", "sealed", dgB, sealedStmt(dgA), true},
		{"sealed absent laneDigest", "sealed", dgA, sealedStmt(""), true},
		{"sealed UC1 present laneDigest", "sealed", "", sealedStmt(dgA), false},
		{"sealed wrong predicateType", "sealed", "", typed("https://example.com/wrong"), true},
		{"engine-context ok", "engine-context", "", typed(engineContextPredicateType), false},
		{"engine-context wrong type", "engine-context", "", typed(sealedPredicateType), true},
		{"informational ok", "informational", "", typed(informationalPredicateType), false},
		{"informational wrong type", "informational", "", typed("https://example.com/wrong"), true},
		{"malformed statement", "sealed", "", []byte("{not json"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePredicate(tt.layer, tt.statement, tt.laneDigest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePredicate(%q) err = %v, wantErr %v", tt.layer, err, tt.wantErr)
			}
		})
	}
}

// TestClassifyLayer covers the V/E gate mapping under both trust modes.
func TestClassifyLayer(t *testing.T) {
	tests := []struct {
		name          string
		layer         string
		noEngineTrust bool
		want          gateClass
	}{
		{"sealed gates V", "sealed", false, gateV},
		{"sealed ignores the flag", "sealed", true, gateV},
		{"engine-context gates E", "engine-context", false, gateE},
		{"engine-context degraded by flag", "engine-context", true, gateNone},
		{"informational never gates", "informational", false, gateNone},
		{"unknown never gates", "speculative", false, gateNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyLayer(tt.layer, tt.noEngineTrust); got != tt.want {
				t.Fatalf("classifyLayer(%q, %v) = %d, want %d", tt.layer, tt.noEngineTrust, got, tt.want)
			}
		})
	}
}

// TestRunVerifyUC2HappyPath: the lane is the policy. All three enriched bundles
// attached; the sealed laneDigest matches the golden lane's digest (the 3a
// construction guarantees it). The golden lane declares no inline trust root,
// so the anchor comes from --trust-root.
func TestRunVerifyUC2HappyPath(t *testing.T) {
	subjectHex := goldenSubjectHex(t, goldenFile(t, "sealed.sigstore.json"))
	host := localRegistry(t)
	attachGoldenLayers(t, host, subjectHex, "sealed", "engine-context", "informational")

	opts := verifyOptions{
		subjectRef:   host + "/app@sha256:" + subjectHex,
		laneFile:     filepath.Join("..", "..", "internal", "verify", "testdata", "golden", "lane.yaml"),
		trustRootRef: goldenTrustRootRef(t, host),
	}
	if err := runVerify(context.Background(), io.Discard, opts); err != nil {
		t.Fatalf("runVerify UC2: %v", err)
	}
}

// TestRunVerifyMissingEngineContext: an absent engine-context layer is an
// E-violation without the flag, and a non-gating "absent" diagnostic with it.
func TestRunVerifyMissingEngineContext(t *testing.T) {
	subjectHex := goldenSubjectHex(t, goldenFile(t, "sealed.sigstore.json"))
	host := localRegistry(t)
	attachGoldenLayers(t, host, subjectHex, "sealed", "informational")

	base := verifyOptions{
		subjectRef:   host + "/app@sha256:" + subjectHex,
		identity:     goldenIdentity,
		issuer:       goldenIssuer,
		trustRootRef: goldenTrustRootRef(t, host),
	}
	if err := runVerify(context.Background(), io.Discard, base); err == nil {
		t.Fatal("want error: an absent engine-context must gate without --no-engine-trust")
	}

	logBuf := captureLog(t)
	withFlag := base
	withFlag.noEngineTrust = true
	if err := runVerify(context.Background(), io.Discard, withFlag); err != nil {
		t.Fatalf("runVerify --no-engine-trust: %v", err)
	}
	if !strings.Contains(logBuf.String(), "engine-context: absent") {
		t.Fatalf("want an engine-context absent diagnostic, got: %q", logBuf.String())
	}
}

// TestRunVerifyMissingInformational: an absent informational layer never gates;
// it is reported and the verify still succeeds.
func TestRunVerifyMissingInformational(t *testing.T) {
	subjectHex := goldenSubjectHex(t, goldenFile(t, "sealed.sigstore.json"))
	host := localRegistry(t)
	attachGoldenLayers(t, host, subjectHex, "sealed", "engine-context")

	logBuf := captureLog(t)
	opts := verifyOptions{
		subjectRef:   host + "/app@sha256:" + subjectHex,
		identity:     goldenIdentity,
		issuer:       goldenIssuer,
		trustRootRef: goldenTrustRootRef(t, host),
	}
	if err := runVerify(context.Background(), io.Discard, opts); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
	if !strings.Contains(logBuf.String(), "informational: absent") {
		t.Fatalf("want an informational absent diagnostic, got: %q", logBuf.String())
	}
}
