package registry_test

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"net/url"
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
