package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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

// goldenTrustRootFile copies the golden trusted_root.json into a temp file and
// returns its path -- the --trust-root override lever, from an arbitrary path.
func goldenTrustRootFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, goldenFile(t, "trusted_root.json"), 0o600); err != nil {
		t.Fatalf("write temp trust root: %v", err)
	}
	return path
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
// subject-match chain with no harness: the golden bundle, the golden trusted
// root via --trust-root, and an in-memory registry. This is the round-trip the
// override lever exists to enable.
func TestRunVerifyHappyPathUC1(t *testing.T) {
	bundle := goldenFile(t, "sealed.sigstore.json")
	subjectHex := goldenSubjectHex(t, bundle)

	host := localRegistry(t)
	attachGolden(t, host, subjectHex, bundle)

	var out bytes.Buffer
	opts := verifyOptions{
		subjectRef: host + "/app@sha256:" + subjectHex,
		identity:   goldenIdentity,
		issuer:     goldenIssuer,
		trustRoot:  goldenTrustRootFile(t),
	}
	if err := runVerify(context.Background(), &out, opts); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
	// The verified in-toto statement, not arbitrary text, must reach stdout.
	var st struct {
		Type    string `json:"_type"`
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
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
		subjectRef: host + "/app@sha256:" + other,
		identity:   goldenIdentity,
		issuer:     goldenIssuer,
		trustRoot:  goldenTrustRootFile(t),
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
		subjectRef: host + "/app@" + subject.Digest.String(),
		identity:   goldenIdentity,
		issuer:     goldenIssuer,
		trustRoot:  goldenTrustRootFile(t),
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
