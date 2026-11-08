package registry_test

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/verify"
)

// localRegistry starts an in-memory OCI registry and returns its
// localhost:<port> host. ggcr dials plain HTTP only for localhost-prefixed
// (and RFC1918) registries, never for 127.0.0.1.
func localRegistry(t *testing.T, referrersAPI bool) string {
	t.Helper()
	srv := httptest.NewServer(regtest.Registry(t, referrersAPI))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return "localhost:" + u.Port()
}

// mustNotWait is the wait of a read that finds every required layer at once:
// it fails the test when it is asked to wait.
func mustNotWait(t *testing.T) func(context.Context, clock.Duration) error {
	t.Helper()
	return func(context.Context, clock.Duration) error {
		t.Error("the read waited, want every required layer at once")
		return nil
	}
}

// pushSubject pushes a minimal OCI image to ref and returns its descriptor.
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

// TestAttachStatementBundles pushes the three statement bundles and reads
// them back from the registry side: each referrer carries the OCI 1.1
// artifact form -- the manifest artifactType and the OCI empty config -- and
// its own bundle bytes under its statement annotation -- and the push returns
// the descriptor of every referrer it pushed, each one the listing holds.
func TestAttachStatementBundles(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/app:v1"
	subject := pushSubject(t, target)

	bundles := []registry.StatementBundle{
		{Statement: record.TrustLayerSealed, Bundle: []byte(`{"bundle":"sealed"}`)},
		{Statement: record.TrustLayerEngineDependent, Bundle: []byte(`{"bundle":"engine-dependent"}`)},
		{Statement: record.TrustLayerInformational, Bundle: []byte(`{"bundle":"informational"}`)},
	}
	attached, err := registry.AttachStatementBundles(context.Background(), target, subject, bundles)
	if err != nil {
		t.Fatalf("AttachStatementBundles: %v", err)
	}

	subjectDigest, err := name.NewDigest(host + "/app@" + subject.Digest.String())
	if err != nil {
		t.Fatalf("subject digest ref: %v", err)
	}
	index, err := remote.Referrers(subjectDigest)
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest: %v", err)
	}
	if len(manifest.Manifests) != len(bundles) {
		t.Fatalf("referrers = %d, want %d", len(manifest.Manifests), len(bundles))
	}
	seen := map[string][]byte{}
	listed := map[v1.Hash]bool{}
	for _, desc := range manifest.Manifests {
		listed[desc.Digest] = true
		if desc.ArtifactType != registry.SigstoreBundleMediaType {
			t.Errorf("artifactType = %q, want %q", desc.ArtifactType, registry.SigstoreBundleMediaType)
		}
		ref, err := name.NewDigest(host + "/app@" + desc.Digest.String())
		if err != nil {
			t.Fatalf("referrer digest ref: %v", err)
		}
		img, err := remote.Image(ref)
		if err != nil {
			t.Fatalf("fetch referrer %s: %v", desc.Digest, err)
		}
		// Annotations live on the manifest; the referrers index omits them.
		imgMfst, err := img.Manifest()
		if err != nil {
			t.Fatalf("referrer manifest %s: %v", desc.Digest, err)
		}
		if imgMfst.ArtifactType != registry.SigstoreBundleMediaType {
			t.Errorf("manifest artifactType = %q, want %q", imgMfst.ArtifactType, registry.SigstoreBundleMediaType)
		}
		if imgMfst.Config.MediaType != types.OCIEmptyJSON || imgMfst.Config.Size != 2 {
			t.Errorf("config = %s (%d bytes), want the OCI empty descriptor", imgMfst.Config.MediaType, imgMfst.Config.Size)
		}
		stmt := imgMfst.Annotations["dev.strike.statement"]
		layers, err := img.Layers()
		if err != nil || len(layers) != 1 {
			t.Fatalf("referrer %s layers: %v (n=%d)", stmt, err, len(layers))
		}
		rc, err := layers[0].Uncompressed()
		if err != nil {
			t.Fatalf("referrer %s layer open: %v", stmt, err)
		}
		content, err := io.ReadAll(rc)
		if cerr := rc.Close(); cerr != nil {
			t.Fatalf("referrer %s layer close: %v", stmt, cerr)
		}
		if err != nil {
			t.Fatalf("referrer %s layer read: %v", stmt, err)
		}
		seen[stmt] = content
	}
	if len(attached) != len(bundles) {
		t.Fatalf("attached = %d descriptors, want %d", len(attached), len(bundles))
	}
	for _, a := range attached {
		if a.ArtifactType != registry.SigstoreBundleMediaType || !listed[a.Digest] {
			t.Errorf("attached %s (artifactType %q) is not a listed sigstore bundle referrer", a.Digest, a.ArtifactType)
		}
	}
	for _, b := range bundles {
		stmt := string(b.Statement)
		got, ok := seen[stmt]
		if !ok {
			t.Errorf("missing referrer annotated %q", stmt)
			continue
		}
		if !strings.Contains(string(got), stmt) {
			t.Errorf("referrer %q content = %q", stmt, got)
		}
	}
}

// TestAttachStatementBundlesRefusesTagFallback: a registry without the
// referrers API fails the push with an error naming the registry and the
// subject digest, and no referrers fallback tag is written.
func TestAttachStatementBundlesRefusesTagFallback(t *testing.T) {
	host := localRegistry(t, false)
	target := host + "/app:v1"
	subject := pushSubject(t, target)
	_, err := registry.AttachStatementBundles(context.Background(), target, subject, []registry.StatementBundle{
		{Statement: record.TrustLayerSealed, Bundle: []byte(`{"bundle":"sealed"}`)},
	})
	if err == nil {
		t.Fatal("AttachStatementBundles succeeded without the referrers API, want error")
	}
	for _, want := range []string{"registry " + host + " does not support the Referrers API", subject.Digest.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	repo, err := name.NewRepository(host + "/app")
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	tags, err := remote.List(repo)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	for _, tag := range tags {
		if strings.HasPrefix(tag, "sha256-") {
			t.Errorf("referrers fallback tag %q was written", tag)
		}
	}
}

// TestFetchStatementBundles attaches the three statement bundles and reads
// them back through the artifactType-filtered referrers listing; the two
// required layers are listed at once, so the read does not wait.
func TestFetchStatementBundles(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/app:v1"
	subject := pushSubject(t, target)

	bundles := []registry.StatementBundle{
		{Statement: record.TrustLayerSealed, Bundle: []byte(`{"bundle":"sealed"}`)},
		{Statement: record.TrustLayerEngineDependent, Bundle: []byte(`{"bundle":"engine-dependent"}`)},
		{Statement: record.TrustLayerInformational, Bundle: []byte(`{"bundle":"informational"}`)},
	}
	if _, err := registry.AttachStatementBundles(context.Background(), target, subject, bundles); err != nil {
		t.Fatalf("AttachStatementBundles: %v", err)
	}

	subjectDigestRef := host + "/app@" + subject.Digest.String()
	got, err := registry.FetchStatementBundles(context.Background(), subjectDigestRef, registry.SystemTransports{},
		[]record.TrustLayer{record.TrustLayerSealed, record.TrustLayerEngineDependent}, mustNotWait(t))
	if err != nil {
		t.Fatalf("FetchStatementBundles: %v", err)
	}
	if len(got) != len(bundles) {
		t.Fatalf("fetched = %d, want %d", len(got), len(bundles))
	}
	gotByName := map[record.TrustLayer][]byte{}
	for _, b := range got {
		gotByName[b.Statement] = b.Bundle
	}
	for _, b := range bundles {
		fetched, ok := gotByName[b.Statement]
		if !ok {
			t.Errorf("missing fetched bundle %q", b.Statement)
			continue
		}
		if !bytes.Equal(fetched, b.Bundle) {
			t.Errorf("bundle %q = %q, want %q", b.Statement, fetched, b.Bundle)
		}
	}
}

// TestFetchStatementBundlesRefusesTagFallback: a registry without the
// referrers API fails the read with an error naming the registry and the
// subject digest, instead of reading a referrers fallback tag.
func TestFetchStatementBundlesRefusesTagFallback(t *testing.T) {
	host := localRegistry(t, false)
	subject := pushSubject(t, host+"/app:v1")
	_, err := registry.FetchStatementBundles(context.Background(), host+"/app@"+subject.Digest.String(), registry.SystemTransports{}, nil, mustNotWait(t))
	if err == nil {
		t.Fatal("FetchStatementBundles succeeded without the referrers API, want error")
	}
	for _, want := range []string{"registry " + host + " does not support the Referrers API", subject.Digest.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestFetchStatementBundlesRejectsTag(t *testing.T) {
	host := localRegistry(t, true)
	if _, err := registry.FetchStatementBundles(context.Background(), host+"/app:v1", registry.SystemTransports{}, nil, mustNotWait(t)); err == nil {
		t.Fatal("FetchStatementBundles accepted a tag reference, want error")
	}
}

func TestFetchStatementBundlesNoReferrers(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/app:v1"
	subject := pushSubject(t, target)
	got, err := registry.FetchStatementBundles(context.Background(), host+"/app@"+subject.Digest.String(), registry.SystemTransports{}, nil, mustNotWait(t))
	if err != nil {
		t.Fatalf("FetchStatementBundles: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("fetched = %d, want 0", len(got))
	}
}

// TestFetchStatementBundlesSkipsUnknownLayer: a referrer whose annotation names
// no trust layer is skipped, and the known layer still comes back.
func TestFetchStatementBundlesSkipsUnknownLayer(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/app:v1"
	subject := pushSubject(t, target)
	bundles := []registry.StatementBundle{
		{Statement: record.TrustLayerSealed, Bundle: []byte(`{"bundle":"sealed"}`)},
		{Statement: "speculative", Bundle: []byte(`{"bundle":"speculative"}`)},
	}
	if _, err := registry.AttachStatementBundles(context.Background(), target, subject, bundles); err != nil {
		t.Fatalf("AttachStatementBundles: %v", err)
	}
	got, err := registry.FetchStatementBundles(context.Background(), host+"/app@"+subject.Digest.String(), registry.SystemTransports{}, nil, mustNotWait(t))
	if err != nil {
		t.Fatalf("FetchStatementBundles: %v", err)
	}
	if len(got) != 1 || got[0].Statement != record.TrustLayerSealed {
		t.Fatalf("fetched %d bundles, want only the sealed one", len(got))
	}
}

// TestFetchStatementBundlesSkipsConfigTypedReferrer: a referrer that carries
// the bundle type only in its config media type is listed under the
// artifactType filter by the OCI fallback rule, but its manifest names no
// artifactType, so the reader skips it and returns only strike's own bundle.
func TestFetchStatementBundlesSkipsConfigTypedReferrer(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/app:v1"
	subject := pushSubject(t, target)
	repo, err := name.NewRepository(host + "/app")
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	pushConfigTypedReferrer(t, repo, subject, registry.SigstoreBundleMediaType, map[string]string{
		"dev.strike.statement": "sealed",
	})
	if _, attachErr := registry.AttachStatementBundles(context.Background(), target, subject, []registry.StatementBundle{
		{Statement: record.TrustLayerInformational, Bundle: []byte(`{"bundle":"informational"}`)},
	}); attachErr != nil {
		t.Fatalf("AttachStatementBundles: %v", attachErr)
	}
	got, err := registry.FetchStatementBundles(context.Background(), host+"/app@"+subject.Digest.String(), registry.SystemTransports{}, nil, mustNotWait(t))
	if err != nil {
		t.Fatalf("FetchStatementBundles: %v", err)
	}
	if len(got) != 1 || got[0].Statement != record.TrustLayerInformational {
		t.Fatalf("fetched %d bundles, want only the informational one", len(got))
	}
}

func TestFetchTrustRootRoundTrip(t *testing.T) {
	golden, err := os.ReadFile("../verify/testdata/golden/trusted_root.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	host := localRegistry(t, true)
	ref := host + "/trust:v1"
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err = mutate.AppendLayers(img, static.NewLayer(golden, types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	nameRef, err := name.ParseReference(ref)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if writeErr := remote.Write(nameRef, img); writeErr != nil {
		t.Fatalf("push trust root: %v", writeErr)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	got, err := registry.FetchTrustRoot(context.Background(), primitive.NewImageRef(host+"/trust@"+digest.String()), registry.SystemTransports{})
	if err != nil {
		t.Fatalf("FetchTrustRoot: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Errorf("fetched bytes differ from golden")
	}
	if _, err := verify.ParseTrustedRoot(got); err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
	}
}

func TestFetchTrustRootRejectsTag(t *testing.T) {
	host := localRegistry(t, true)
	if _, err := registry.FetchTrustRoot(context.Background(), primitive.NewImageRef(host+"/trust:v1"), registry.SystemTransports{}); err == nil {
		t.Fatal("FetchTrustRoot accepted a tag reference, want error")
	}
}

// pushBaseSBOMReferrer attaches one cosign-style SBOM attestation referrer of
// subject under repo: a single bundle-typed layer carrying content, cosign's
// predicate-type annotation, and an artifact type discoverable by the referrers
// filter. Returns the referrer manifest digest.
func pushBaseSBOMReferrer(t *testing.T, repo name.Repository, subject v1.Descriptor, predicateType string, content []byte) string {
	t.Helper()
	img, err := registry.ArtifactImage(content, registry.SigstoreBundleMediaType, subject, map[string]string{
		"dev.sigstore.bundle.predicateType": predicateType,
	})
	if err != nil {
		t.Fatalf("artifact image: %v", err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := remote.Write(repo.Digest(digest.String()), img); err != nil {
		t.Fatalf("write referrer: %v", err)
	}
	return digest.String()
}

// pushConfigTypedReferrer attaches a referrer of subject under repo that
// carries the bundle type only in its config media type, with no manifest
// artifactType, and a single layer of layerType under the given annotations.
func pushConfigTypedReferrer(t *testing.T, repo name.Repository, subject v1.Descriptor, layerType types.MediaType, annotations map[string]string) {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err := mutate.AppendLayers(img, static.NewLayer([]byte(`{"bundle":"config-typed"}`), layerType))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	img = mutate.ConfigMediaType(img, registry.SigstoreBundleMediaType)
	annotated, ok := mutate.Annotations(img, annotations).(v1.Image)
	if !ok {
		t.Fatal("unexpected type from mutate.Annotations")
	}
	withSubject, ok := mutate.Subject(annotated, subject).(v1.Image)
	if !ok {
		t.Fatal("unexpected type from mutate.Subject")
	}
	digest, err := withSubject.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := remote.Write(repo.Digest(digest.String()), withSubject); err != nil {
		t.Fatalf("write referrer: %v", err)
	}
}

// TestFetchBaseSBOMReferrers reads base SBOM referrers in the form cosign
// produces -- manifest artifactType, OCI empty config -- through the
// artifactType-filtered listing.
func TestFetchBaseSBOMReferrers(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/base:v1"
	subject := pushSubject(t, target)
	repo, err := name.NewRepository(host + "/base")
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	cdxDigest := pushBaseSBOMReferrer(t, repo, subject, "https://cyclonedx.org/bom", []byte("cdx-bundle"))
	pushBaseSBOMReferrer(t, repo, subject, "https://spdx.dev/Document", []byte("spdx-bundle"))
	// A non-SBOM attestation under the same artifactType filter: must be skipped.
	pushBaseSBOMReferrer(t, repo, subject, "https://slsa.dev/provenance/v1", []byte("slsa-bundle"))

	got, err := registry.FetchBaseSBOMReferrers(context.Background(), primitive.NewImageRef(host+"/base@"+subject.Digest.String()), registry.SystemTransports{})
	if err != nil {
		t.Fatalf("FetchBaseSBOMReferrers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("fetched %d SBOM referrers, want 2 (cyclonedx + spdx; slsa skipped)", len(got))
	}
	byPredicate := map[string]registry.BaseSBOMReferrer{}
	for _, r := range got {
		byPredicate[r.PredicateType] = r
	}
	cdx, ok := byPredicate["https://cyclonedx.org/bom"]
	if !ok {
		t.Fatal("cyclonedx referrer missing")
	}
	if !bytes.Equal(cdx.Bundle, []byte("cdx-bundle")) {
		t.Errorf("cyclonedx bundle = %q, want %q", cdx.Bundle, "cdx-bundle")
	}
	if cdx.Digest != cdxDigest {
		t.Errorf("cyclonedx digest = %q, want %q", cdx.Digest, cdxDigest)
	}
	if _, ok := byPredicate["https://spdx.dev/Document"]; !ok {
		t.Fatal("spdx referrer missing")
	}
}

func TestFetchBaseSBOMReferrersSkipsStrikeOwnBundle(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/base:v1"
	subject := pushSubject(t, target)
	// strike's own producer convention: discoverable, but no SBOM predicate-type
	// annotation, so it is not a base SBOM and must be skipped.
	if _, err := registry.AttachStatementBundles(context.Background(), target, subject, []registry.StatementBundle{
		{Statement: record.TrustLayerSealed, Bundle: []byte("strike-bundle")},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, err := registry.FetchBaseSBOMReferrers(context.Background(), primitive.NewImageRef(host+"/base@"+subject.Digest.String()), registry.SystemTransports{})
	if err != nil {
		t.Fatalf("FetchBaseSBOMReferrers: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("fetched %d, want 0 (strike's own bundle is not a base SBOM)", len(got))
	}
}

func TestFetchBaseSBOMReferrersRejectsTag(t *testing.T) {
	host := localRegistry(t, true)
	if _, err := registry.FetchBaseSBOMReferrers(context.Background(), primitive.NewImageRef(host+"/base:v1"), registry.SystemTransports{}); err == nil {
		t.Fatal("accepted a tag reference, want error")
	}
}

// TestFetchBaseSBOMReferrersRejectsNonBundleLayer: a referrer that selects as
// a base SBOM but carries its layer under another media type is malformed and
// fails the read instead of vanishing.
func TestFetchBaseSBOMReferrersRejectsNonBundleLayer(t *testing.T) {
	host := localRegistry(t, true)
	subject := pushSubject(t, host+"/base:v1")
	repo, err := name.NewRepository(host + "/base")
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	pushConfigTypedReferrer(t, repo, subject, types.OCILayer, map[string]string{
		"dev.sigstore.bundle.predicateType": registry.PredicateTypeCycloneDX,
	})
	_, err = registry.FetchBaseSBOMReferrers(context.Background(), primitive.NewImageRef(host+"/base@"+subject.Digest.String()), registry.SystemTransports{})
	if err == nil || !strings.Contains(err.Error(), "layer media type") {
		t.Fatalf("err = %v, want a layer media type error", err)
	}
}

func TestFetchBaseSBOMReferrersNoReferrers(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/base:v1"
	subject := pushSubject(t, target)
	got, err := registry.FetchBaseSBOMReferrers(context.Background(), primitive.NewImageRef(host+"/base@"+subject.Digest.String()), registry.SystemTransports{})
	if err != nil {
		t.Fatalf("FetchBaseSBOMReferrers: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("fetched %d, want 0", len(got))
	}
}
