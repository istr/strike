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

// localRegistry starts an in-memory OCI registry and returns its
// localhost:<port> host. ggcr dials plain HTTP only for localhost-prefixed
// (and RFC1918) registries, never for 127.0.0.1.
func localRegistry(t *testing.T, referrersAPI bool) string {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.WithReferrersSupport(referrersAPI)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return "localhost:" + u.Port()
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

func testAttach(t *testing.T, referrersAPI bool) {
	t.Helper()
	host := localRegistry(t, referrersAPI)
	target := host + "/app:v1"
	subject := pushSubject(t, target)

	bundles := []registry.StatementBundle{
		{Statement: "sealed", Bundle: []byte(`{"bundle":"sealed"}`)},
		{Statement: "engine-context", Bundle: []byte(`{"bundle":"engine-context"}`)},
		{Statement: "informational", Bundle: []byte(`{"bundle":"informational"}`)},
	}
	if err := registry.AttachStatementBundles(context.Background(), target, subject, bundles); err != nil {
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
	for _, desc := range manifest.Manifests {
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
	for _, b := range bundles {
		got, ok := seen[b.Statement]
		if !ok {
			t.Errorf("missing referrer annotated %q", b.Statement)
			continue
		}
		if !strings.Contains(string(got), b.Statement) {
			t.Errorf("referrer %q content = %q", b.Statement, got)
		}
	}
}

func TestAttachStatementBundlesReferrersAPI(t *testing.T) {
	testAttach(t, true)
}

func TestAttachStatementBundlesFallbackTag(t *testing.T) {
	testAttach(t, false)
}

func testFetch(t *testing.T, referrersAPI bool) {
	t.Helper()
	host := localRegistry(t, referrersAPI)
	target := host + "/app:v1"
	subject := pushSubject(t, target)

	bundles := []registry.StatementBundle{
		{Statement: "sealed", Bundle: []byte(`{"bundle":"sealed"}`)},
		{Statement: "engine-context", Bundle: []byte(`{"bundle":"engine-context"}`)},
		{Statement: "informational", Bundle: []byte(`{"bundle":"informational"}`)},
	}
	if err := registry.AttachStatementBundles(context.Background(), target, subject, bundles); err != nil {
		t.Fatalf("AttachStatementBundles: %v", err)
	}

	subjectDigestRef := host + "/app@" + subject.Digest.String()
	got, err := registry.FetchStatementBundles(context.Background(), subjectDigestRef)
	if err != nil {
		t.Fatalf("FetchStatementBundles: %v", err)
	}
	if len(got) != len(bundles) {
		t.Fatalf("fetched = %d, want %d", len(got), len(bundles))
	}
	gotByName := map[string][]byte{}
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

func TestFetchStatementBundlesReferrersAPI(t *testing.T) {
	testFetch(t, true)
}

func TestFetchStatementBundlesFallbackTag(t *testing.T) {
	testFetch(t, false)
}

func TestFetchStatementBundlesRejectsTag(t *testing.T) {
	host := localRegistry(t, true)
	if _, err := registry.FetchStatementBundles(context.Background(), host+"/app:v1"); err == nil {
		t.Fatal("FetchStatementBundles accepted a tag reference, want error")
	}
}

func TestFetchStatementBundlesNoReferrers(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/app:v1"
	subject := pushSubject(t, target)
	got, err := registry.FetchStatementBundles(context.Background(), host+"/app@"+subject.Digest.String())
	if err != nil {
		t.Fatalf("FetchStatementBundles: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("fetched = %d, want 0", len(got))
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

	got, err := registry.FetchTrustRoot(context.Background(), host+"/trust@"+digest.String())
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
	if _, err := registry.FetchTrustRoot(context.Background(), host+"/trust:v1"); err == nil {
		t.Fatal("FetchTrustRoot accepted a tag reference, want error")
	}
}

func TestCopyImageReturnsPushedDescriptor(t *testing.T) {
	host := localRegistry(t, true)
	src := host + "/src:v1"
	want := pushSubject(t, src)

	dst := host + "/dst:v1"
	got, err := registry.CopyImage(src, dst)
	if err != nil {
		t.Fatalf("CopyImage: %v", err)
	}
	if got.Digest != want.Digest {
		t.Errorf("descriptor digest = %s, want %s", got.Digest, want.Digest)
	}
	dstRef, err := name.NewDigest(host + "/dst@" + want.Digest.String())
	if err != nil {
		t.Fatalf("dst digest ref: %v", err)
	}
	if _, err := remote.Head(dstRef); err != nil {
		t.Errorf("copied manifest not at target: %v", err)
	}
}

// pushBaseSBOMReferrer attaches one cosign-style SBOM attestation referrer of
// subject under repo: a single bundle-typed layer carrying content, cosign's
// predicate-type annotation, and an artifact type discoverable by the referrers
// filter. Returns the referrer manifest digest.
func pushBaseSBOMReferrer(t *testing.T, repo name.Repository, subject v1.Descriptor, predicateType string, content []byte) string {
	t.Helper()
	img, err := registry.ArtifactImage(content, registry.SigstoreBundleMediaType, subject)
	if err != nil {
		t.Fatalf("artifact image: %v", err)
	}
	img = mutate.ConfigMediaType(img, types.MediaType(registry.SigstoreBundleMediaType))
	annotated, ok := mutate.Annotations(img, map[string]string{
		"dev.sigstore.bundle.predicateType": predicateType,
	}).(v1.Image)
	if !ok {
		t.Fatal("annotate: unexpected type")
	}
	withSubject, ok := mutate.Subject(annotated, subject).(v1.Image)
	if !ok {
		t.Fatal("subject: unexpected type")
	}
	digest, err := withSubject.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := remote.Write(repo.Digest(digest.String()), withSubject); err != nil {
		t.Fatalf("write referrer: %v", err)
	}
	return digest.String()
}

// The cosign-faithful empty-config path (artifactType on the manifest field,
// OCI empty config) is covered by the deferred live e2e (2c-ii / E4): the
// in-memory ggcr registry indexes a referrer's artifactType from config.mediaType
// only, so it cannot make such a referrer discoverable by the artifactType filter.
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

	got, err := registry.FetchBaseSBOMReferrers(context.Background(), host+"/base@"+subject.Digest.String())
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
	if err := registry.AttachStatementBundles(context.Background(), target, subject, []registry.StatementBundle{
		{Statement: "sealed", Bundle: []byte("strike-bundle")},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, err := registry.FetchBaseSBOMReferrers(context.Background(), host+"/base@"+subject.Digest.String())
	if err != nil {
		t.Fatalf("FetchBaseSBOMReferrers: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("fetched %d, want 0 (strike's own bundle is not a base SBOM)", len(got))
	}
}

func TestFetchBaseSBOMReferrersRejectsTag(t *testing.T) {
	host := localRegistry(t, true)
	if _, err := registry.FetchBaseSBOMReferrers(context.Background(), host+"/base:v1"); err == nil {
		t.Fatal("accepted a tag reference, want error")
	}
}

func TestFetchBaseSBOMReferrersNoReferrers(t *testing.T) {
	host := localRegistry(t, true)
	target := host + "/base:v1"
	subject := pushSubject(t, target)
	got, err := registry.FetchBaseSBOMReferrers(context.Background(), host+"/base@"+subject.Digest.String())
	if err != nil {
		t.Fatalf("FetchBaseSBOMReferrers: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("fetched %d, want 0", len(got))
	}
}
