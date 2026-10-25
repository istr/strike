package registry_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
)

const refNameAnnotation = "org.opencontainers.image.ref.name"

// storeEngine fakes the engine store for the materialization path: which
// references resolve, what a load returns, which id an inspect reports, and
// every call made.
type storeEngine struct {
	container.Engine
	loadErr   error
	present   map[string]bool
	identity  *container.EngineIdentity
	inspectID string
	loaded    [][]byte
	exists    []string
	inspected []string
}

func (e *storeEngine) ImageExists(_ context.Context, ref string) (bool, error) {
	e.exists = append(e.exists, ref)
	return e.present[ref], nil
}

func (e *storeEngine) ImageLoad(_ context.Context, input io.Reader) (string, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return "", err
	}
	if e.loadErr != nil {
		return "", e.loadErr
	}
	e.loaded = append(e.loaded, data)
	return "loaded", nil
}

func (e *storeEngine) ImageInspect(_ context.Context, ref string) (*container.ImageInfo, error) {
	e.inspected = append(e.inspected, ref)
	if len(e.loaded) == 0 {
		return nil, errors.New("image " + ref + " not found")
	}
	return &container.ImageInfo{ID: e.inspectID}, nil
}

func (e *storeEngine) Identity() *container.EngineIdentity { return e.identity }

func amd64Engine() *container.EngineIdentity {
	return &container.EngineIdentity{Runtime: &container.RuntimeInfo{OS: "linux", Arch: "amd64"}}
}

// testRegistry serves an in-process registry behind handler wrappers and
// returns its host:port. localhost is served over plain HTTP by
// go-containerregistry, never 127.0.0.1.
func testRegistry(t *testing.T, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	h := ggcrregistry.New()
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return "localhost:" + u.Port()
}

// tamperWhere serves inner's answers, inverting the last body byte of every
// GET whose path match accepts. Lengths are unchanged, so only the content
// check can notice.
func tamperWhere(match func(path string) bool) func(http.Handler) http.Handler {
	return func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || !match(r.URL.Path) {
				inner.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			inner.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if len(body) > 0 {
				body[len(body)-1] ^= 0xff
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			if _, err := w.Write(body); err != nil {
				panic(err)
			}
		})
	}
}

// testImage builds a one-layer OCI image whose layer holds content.
func testImage(t *testing.T, content string) v1.Image {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	img, err := mutate.AppendLayers(img, static.NewLayer([]byte(content), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	return img
}

// platformImage is one entry of a pushed index.
type platformImage struct {
	image    v1.Image
	platform v1.Platform
}

// pushIndex pushes an index of the given platform images to repo and returns
// the declared reference (by index digest), the index digest and the raw
// index bytes.
func pushIndex(t *testing.T, repo string, children []platformImage) (primitive.ImageRef, v1.Hash, []byte) {
	t.Helper()
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	for i := range children {
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        children[i].image,
			Descriptor: v1.Descriptor{Platform: &children[i].platform},
		})
	}
	tag, err := name.ParseReference(repo + ":pushed")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if wErr := remote.WriteIndex(tag, idx); wErr != nil {
		t.Fatalf("push index: %v", wErr)
	}
	digest, err := idx.Digest()
	if err != nil {
		t.Fatalf("index digest: %v", err)
	}
	raw, err := idx.RawManifest()
	if err != nil {
		t.Fatalf("raw index: %v", err)
	}
	return primitive.ImageRef(repo + "@" + digest.String()), digest, raw
}

// pushImage pushes img to repo and returns the declared reference by manifest
// digest.
func pushImage(t *testing.T, repo string, img v1.Image) (primitive.ImageRef, v1.Hash) {
	t.Helper()
	tag, err := name.ParseReference(repo + ":pushed")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if wErr := remote.Write(tag, img); wErr != nil {
		t.Fatalf("push image: %v", wErr)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	return primitive.ImageRef(repo + "@" + digest.String()), digest
}

func configHex(t *testing.T, img v1.Image) string {
	t.Helper()
	h, err := img.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}
	return h.Hex
}

func digestOf(t *testing.T, img v1.Image) v1.Hash {
	t.Helper()
	h, err := img.Digest()
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	return h
}

// layoutEntries reads the tar back: entry names in order, and the bytes of
// index.json and of every blob.
func layoutEntries(t *testing.T, data []byte) ([]string, map[string][]byte) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read layout tar: %v", err)
		}
		names = append(names, hdr.Name)
		if hdr.Typeflag == tar.TypeReg {
			body, readErr := io.ReadAll(tr)
			if readErr != nil {
				t.Fatalf("read %s: %v", hdr.Name, readErr)
			}
			files[hdr.Name] = body
		}
	}
	return names, files
}

func TestEnsureImage_IndexLoadsDeclaredDigest(t *testing.T) {
	host := testRegistry(t, nil)
	amd := testImage(t, "amd64 rootfs")
	arm := testImage(t, "arm64 rootfs")
	ref, indexDigest, rawIndex := pushIndex(t, host+"/t/img", []platformImage{
		{platform: v1.Platform{OS: "linux", Architecture: "amd64"}, image: amd},
		{platform: v1.Platform{OS: "linux", Architecture: "arm64"}, image: arm},
	})
	eng := &storeEngine{identity: amd64Engine(), inspectID: configHex(t, amd)}

	if err := (&registry.Client{Engine: eng}).EnsureImage(context.Background(), ref); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	if len(eng.loaded) != 1 {
		t.Fatalf("loads = %d, want 1", len(eng.loaded))
	}
	if got := eng.exists; len(got) != 1 || got[0] != string(ref) {
		t.Errorf("exists calls = %v, want [%s]", got, ref)
	}
	if got := eng.inspected; len(got) != 1 || got[0] != string(ref) {
		t.Errorf("inspect calls = %v, want [%s]", got, ref)
	}

	names, files := layoutEntries(t, eng.loaded[0])
	var idx v1.IndexManifest
	if err := json.Unmarshal(files["index.json"], &idx); err != nil {
		t.Fatalf("index.json: %v", err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("index.json manifests = %d, want 1", len(idx.Manifests))
	}
	top := idx.Manifests[0]
	if top.Digest != indexDigest || top.MediaType != types.OCIImageIndex || top.Size != int64(len(rawIndex)) {
		t.Errorf("index.json names %s %s %d, want %s %s %d", top.Digest, top.MediaType, top.Size, indexDigest, types.OCIImageIndex, len(rawIndex))
	}
	if top.Annotations[refNameAnnotation] != string(ref) {
		t.Errorf("ref.name = %q, want %q", top.Annotations[refNameAnnotation], ref)
	}
	if !bytes.Equal(files["blobs/sha256/"+indexDigest.Hex], rawIndex) {
		t.Errorf("the raw index blob is missing or differs")
	}
	amdDigest := digestOf(t, amd)
	armDigest := digestOf(t, arm)
	if _, ok := files["blobs/sha256/"+amdDigest.Hex]; !ok {
		t.Errorf("the amd64 manifest blob is missing")
	}
	if _, ok := files["blobs/sha256/"+armDigest.Hex]; ok {
		t.Errorf("the arm64 manifest blob is present; only the engine's platform is loaded")
	}
	indexAt := -1
	lastBlob := -1
	for i, n := range names {
		switch {
		case n == "index.json":
			indexAt = i
		case strings.HasPrefix(n, "blobs/sha256/") && n != "blobs/sha256/":
			lastBlob = i
		}
	}
	if indexAt < 0 || lastBlob < 0 || indexAt < lastBlob {
		t.Errorf("index.json at %d, last blob at %d: every blob must precede index.json", indexAt, lastBlob)
	}
}

func TestEnsureImage_ManifestDigestNamesTheManifest(t *testing.T) {
	host := testRegistry(t, nil)
	img := testImage(t, "single rootfs")
	ref, manifestDigest := pushImage(t, host+"/t/single", img)
	eng := &storeEngine{identity: amd64Engine(), inspectID: configHex(t, img)}

	if err := (&registry.Client{Engine: eng}).EnsureImage(context.Background(), ref); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	names, files := layoutEntries(t, eng.loaded[0])
	var idx v1.IndexManifest
	if err := json.Unmarshal(files["index.json"], &idx); err != nil {
		t.Fatalf("index.json: %v", err)
	}
	if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != manifestDigest || idx.Manifests[0].MediaType != types.OCIManifestSchema1 {
		t.Errorf("index.json = %+v, want the manifest %s", idx.Manifests, manifestDigest)
	}
	if idx.Manifests[0].Annotations[refNameAnnotation] != string(ref) {
		t.Errorf("ref.name = %q, want %q", idx.Manifests[0].Annotations[refNameAnnotation], ref)
	}
	blobs := 0
	for _, n := range names {
		if n == "blobs/sha256/"+manifestDigest.Hex {
			blobs++
		}
	}
	if blobs != 1 {
		t.Errorf("manifest blob written %d times, want exactly once", blobs)
	}
}

func TestEnsureImage_PresentFetchesNothing(t *testing.T) {
	host := testRegistry(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected registry call: %s %s", r.Method, r.URL.Path)
		})
	})
	declared := host + "/t/img@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	eng := &storeEngine{present: map[string]bool{declared: true}}

	if err := (&registry.Client{Engine: eng}).EnsureImage(context.Background(), primitive.NewImageRef(declared)); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	if len(eng.loaded) != 0 || len(eng.inspected) != 0 {
		t.Errorf("loads = %d, inspects = %d, want none", len(eng.loaded), len(eng.inspected))
	}
}

func TestEnsureImage_Failures(t *testing.T) {
	tests := []struct {
		name     string
		wrap     func(http.Handler) http.Handler
		engine   func(amd v1.Image) *storeEngine
		declare  func(host string, amd, other v1.Image) primitive.ImageRef
		wantErr  string
		wantLoad bool
	}{
		{
			name: "platform unknown",
			engine: func(v1.Image) *storeEngine {
				return &storeEngine{identity: &container.EngineIdentity{}}
			},
			declare: func(host string, amd, _ v1.Image) primitive.ImageRef {
				ref, _ := pushImage(t, host+"/t/unknown", amd)
				return ref
			},
			wantErr: "engine platform unknown",
		},
		{
			name:   "not pinned by digest",
			engine: func(v1.Image) *storeEngine { return &storeEngine{identity: amd64Engine()} },
			declare: func(host string, _, _ v1.Image) primitive.ImageRef {
				return primitive.ImageRef(host + "/t/img:latest")
			},
			wantErr: "not pinned by digest",
		},
		{
			name:   "digest absent from the registry",
			engine: func(v1.Image) *storeEngine { return &storeEngine{identity: amd64Engine()} },
			declare: func(host string, _, _ v1.Image) primitive.ImageRef {
				return primitive.ImageRef(host + "/t/img@sha256:0000000000000000000000000000000000000000000000000000000000000001")
			},
			wantErr: "fetch",
		},
		{
			name:   "no manifest for the engine platform",
			engine: func(v1.Image) *storeEngine { return &storeEngine{identity: amd64Engine()} },
			declare: func(host string, _, other v1.Image) primitive.ImageRef {
				ref, _, _ := pushIndex(t, host+"/t/arm", []platformImage{
					{platform: v1.Platform{OS: "linux", Architecture: "arm64"}, image: other},
				})
				return ref
			},
			wantErr: "no manifest for linux/amd64",
		},
		{
			name:   "two manifests for the platform and no variant to decide",
			engine: func(v1.Image) *storeEngine { return &storeEngine{identity: amd64Engine()} },
			declare: func(host string, amd, other v1.Image) primitive.ImageRef {
				ref, _, _ := pushIndex(t, host+"/t/twice", []platformImage{
					{platform: v1.Platform{OS: "linux", Architecture: "amd64", Variant: "v2"}, image: amd},
					{platform: v1.Platform{OS: "linux", Architecture: "amd64", Variant: "v3"}, image: other},
				})
				return ref
			},
			wantErr: "does not decide",
		},
		{
			name:   "manifest bytes do not match the declared digest",
			wrap:   tamperWhere(func(path string) bool { return strings.Contains(path, "/manifests/sha256:") }),
			engine: func(v1.Image) *storeEngine { return &storeEngine{identity: amd64Engine()} },
			declare: func(host string, amd, _ v1.Image) primitive.ImageRef {
				ref, _ := pushImage(t, host+"/t/badmanifest", amd)
				return ref
			},
			wantErr: "does not match requested digest",
		},
		{
			name: "load error",
			engine: func(v1.Image) *storeEngine {
				return &storeEngine{identity: amd64Engine(), loadErr: errors.New("status 500: engine said no")}
			},
			declare: func(host string, amd, _ v1.Image) primitive.ImageRef {
				ref, _ := pushImage(t, host+"/t/loaderr", amd)
				return ref
			},
			wantErr: "load: status 500",
		},
		{
			name: "store resolves the reference to another config",
			engine: func(v1.Image) *storeEngine {
				return &storeEngine{identity: amd64Engine(), inspectID: "0000000000000000000000000000000000000000000000000000000000000000"}
			},
			declare: func(host string, amd, _ v1.Image) primitive.ImageRef {
				ref, _ := pushImage(t, host+"/t/wrongid", amd)
				return ref
			},
			wantErr:  "fetched config is",
			wantLoad: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := testRegistry(t, tt.wrap)
			amd := testImage(t, "amd64 rootfs "+tt.name)
			other := testImage(t, "other rootfs "+tt.name)
			ref := tt.declare(host, amd, other)
			eng := tt.engine(amd)
			err := (&registry.Client{Engine: eng}).EnsureImage(context.Background(), ref)
			if err == nil {
				t.Fatalf("EnsureImage = nil error, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			declared := string(ref)
			if !strings.Contains(err.Error(), declared) {
				t.Errorf("error = %q, want it to name %q", err, ref)
			}
			if (len(eng.loaded) > 0) != tt.wantLoad {
				t.Errorf("loads = %d, wantLoad %v", len(eng.loaded), tt.wantLoad)
			}
		})
	}
}

// TestEnsureImage_CorruptBlobAbortsTheStream pins the control-plane check
// that the engine does not perform: a layer whose bytes do not hash to the
// manifest's digest fails the materialization, and the engine receives no
// complete layout. The fake engine's ImageLoad reads the stream to its end
// and returns the stream error.
func TestEnsureImage_CorruptBlobAbortsTheStream(t *testing.T) {
	amd := testImage(t, "amd64 rootfs with a layer to corrupt")
	layers, err := amd.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}
	layerDigest, err := layers[0].Digest()
	if err != nil {
		t.Fatalf("layer digest: %v", err)
	}
	host := testRegistry(t, tamperWhere(func(path string) bool { return strings.HasSuffix(path, "/blobs/"+layerDigest.String()) }))
	ref, _ := pushImage(t, host+"/t/badblob", amd)
	eng := &storeEngine{identity: amd64Engine(), inspectID: configHex(t, amd)}

	err = (&registry.Client{Engine: eng}).EnsureImage(context.Background(), ref)
	if err == nil {
		t.Fatal("EnsureImage = nil error on a corrupted layer")
	}
	declared := string(ref)
	if !strings.Contains(err.Error(), declared) {
		t.Errorf("error = %q, want it to name %q", err, ref)
	}
	if strings.Contains(err.Error(), "load:") {
		t.Errorf("error = %q: the verification failure must win over the load failure it causes", err)
	}
	if len(eng.loaded) != 0 || len(eng.inspected) != 0 {
		t.Errorf("loads = %d, inspects = %d, want none after a verification failure", len(eng.loaded), len(eng.inspected))
	}
}

func TestEnsureImage_VariantDecides(t *testing.T) {
	host := testRegistry(t, nil)
	v6 := testImage(t, "arm v6")
	v7 := testImage(t, "arm v7")
	ref, _, _ := pushIndex(t, host+"/t/arm", []platformImage{
		{platform: v1.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}, image: v6},
		{platform: v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, image: v7},
	})
	eng := &storeEngine{
		identity:  &container.EngineIdentity{Runtime: &container.RuntimeInfo{OS: "linux", Arch: "arm", Variant: "v7"}},
		inspectID: configHex(t, v7),
	}
	if err := (&registry.Client{Engine: eng}).EnsureImage(context.Background(), ref); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	_, files := layoutEntries(t, eng.loaded[0])
	v7Digest := digestOf(t, v7)
	v6Digest := digestOf(t, v6)
	if _, ok := files["blobs/sha256/"+v7Digest.Hex]; !ok {
		t.Errorf("the v7 manifest blob is missing")
	}
	if _, ok := files["blobs/sha256/"+v6Digest.Hex]; ok {
		t.Errorf("the v6 manifest blob is present")
	}
}
