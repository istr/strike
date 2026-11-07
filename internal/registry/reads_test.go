package registry_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

// readFixture is a registry that redirects reads to a storage host, and the
// image a test reads from it. Both serve over TLS with the one httptest
// certificate; a plaintext writer on the same store pushes the image. The
// storage is addressed by a name under the reserved .test TLD, which the
// hermetic resolver answers with the loopback: go-containerregistry refuses a
// token realm on a loopback address before it sends a request, so only a name
// lets a realm on the storage reach the read policy.
type readFixture struct {
	trust    endpoint.Certificate
	registry string
	storage  string
	ref      primitive.ImageRef
}

// Registry behaviors a readFixture can take on.
const (
	redirectBlobs     = "blobs"     // every blob GET answers 307 to the storage
	redirectManifests = "manifests" // the manifest GET answers 307 to the storage as well
	realmOnStorage    = "realm"     // every request is challenged with a token realm on the storage
)

func newReadFixture(t *testing.T, behavior string) readFixture {
	t.Helper()
	store := ggcrregistry.New()
	writer := httptest.NewServer(store)
	t.Cleanup(writer.Close)
	u, err := url.Parse(writer.URL)
	if err != nil {
		t.Fatalf("parse writer url: %v", err)
	}
	img, err := mutate.AppendLayers(mutate.MediaType(empty.Image, types.OCIManifestSchema1), static.NewLayer([]byte("read me"), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	tag, err := name.ParseReference("localhost:" + u.Port() + "/t/img:pushed")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if wErr := remote.Write(tag, img); wErr != nil {
		t.Fatalf("push: %v", wErr)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// The registry redirects exactly the paths of the pushed image's blobs,
	// and for redirectManifests its manifest, so no request data reaches a
	// redirect target.
	cfg, err := img.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}
	redirected := []string{"/v2/t/img/blobs/" + cfg.String()}
	for _, l := range layers {
		d, dErr := l.Digest()
		if dErr != nil {
			t.Fatalf("layer digest: %v", dErr)
		}
		redirected = append(redirected, "/v2/t/img/blobs/"+d.String())
	}
	if behavior == redirectManifests {
		redirected = append(redirected, "/v2/t/img/manifests/"+digest.String())
	}

	storage := httptest.NewTLSServer(store)
	t.Cleanup(storage.Close)
	su, err := url.Parse(storage.URL)
	if err != nil {
		t.Fatalf("parse storage url: %v", err)
	}
	storageAuth := "storage.test:" + su.Port()
	reg := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if behavior == realmOnStorage {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+storageAuth+`/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		for _, p := range redirected {
			if r.Method == http.MethodGet && r.URL.Path == p {
				http.Redirect(w, r, "https://"+storageAuth+p, http.StatusTemporaryRedirect)
				return
			}
		}
		store.ServeHTTP(w, r)
	}))
	t.Cleanup(reg.Close)
	regAuth := reg.Listener.Addr().String()
	return readFixture{
		trust:    endpoint.CertificateFromDER(reg.Certificate().Raw, endpoint.CertificateModeLeaf),
		registry: regAuth,
		storage:  storageAuth,
		ref:      primitive.ImageRef(regAuth + "/t/img@" + digest.String()),
	}
}

// reads declares the fixture's registry, with its storage when withStorage,
// and resolves every name through a hermetic DoT resolver to the loopback.
func (f readFixture) reads(t *testing.T, withStorage bool) *registry.Reads {
	t.Helper()
	reg := lane.Registry{Registry: endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority(f.registry), Trust: f.trust}}
	if withStorage {
		reg.Storages = []endpoint.TLS{{Type: "https", Address: endpoint.MustParseAuthority(f.storage), Trust: f.trust}}
	}
	dialer := testutil.StartDoTResolver(t, netip.MustParseAddr("127.0.0.1"))
	return registry.NewReads(dialer, &lane.Lane{Registries: []lane.Registry{reg}})
}

// readImage reads ref through src in full: the manifest, the config, and every
// layer blob.
func readImage(src registry.Transports, ref primitive.ImageRef) error {
	rt, err := src.Transport(ref)
	if err != nil {
		return err
	}
	written := string(ref)
	d, err := name.NewDigest(written)
	if err != nil {
		return err
	}
	img, err := remote.Image(d, remote.WithTransport(rt), remote.WithContext(context.Background()))
	if err != nil {
		return err
	}
	if _, cfgErr := img.RawConfigFile(); cfgErr != nil {
		return cfgErr
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for _, l := range layers {
		rc, openErr := l.Compressed()
		if openErr != nil {
			return openErr
		}
		_, copyErr := io.Copy(io.Discard, rc)
		closeErr := rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// TestReads_Policy pins the read policy of a lane run: a blob read follows
// the registry's redirect to a storage the registry declares, and fails when
// the storage is not declared; a manifest redirect to a declared storage
// fails, and so does a token realm on any host but the registry's own.
func TestReads_Policy(t *testing.T) {
	tests := []struct {
		name        string
		behavior    string
		wantErr     string
		withStorage bool
	}{
		{name: "blob redirect to a declared storage", behavior: redirectBlobs, withStorage: true},
		{name: "blob redirect to an undeclared storage", behavior: redirectBlobs, wantErr: "nor a blob redirect of it to one of its storages"},
		{name: "manifest redirect to a declared storage", behavior: redirectManifests, withStorage: true, wantErr: "nor a blob redirect of it to one of its storages"},
		{name: "token realm on a declared storage", behavior: realmOnStorage, withStorage: true, wantErr: "nor a blob redirect of it to one of its storages"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newReadFixture(t, tt.behavior)
			err := readImage(f.reads(t, tt.withStorage), f.ref)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("read error = %v, want it to contain %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), f.storage) {
				t.Errorf("read error = %v, want it to name the storage %s", err, f.storage)
			}
		})
	}
}

// TestReads_TransportRefusals pins the refusals before any request: a
// reference that does not parse, a registry the lane does not declare, and a
// Reads without a dialer.
func TestReads_TransportRefusals(t *testing.T) {
	dialer := testutil.StartDoTResolver(t, netip.MustParseAddr("127.0.0.1"))
	declared := registry.NewReads(dialer, &lane.Lane{})
	pinned := primitive.ImageRef("images.example.com/x@sha256:" + strings.Repeat("ab", 32))
	tests := []struct {
		reads   *registry.Reads
		name    string
		ref     primitive.ImageRef
		wantErr string
	}{
		{name: "unparseable reference", reads: declared, ref: "images.example.com/x@sha256:abc", wantErr: "registry read images.example.com/x@sha256:abc"},
		{name: "undeclared registry", reads: declared, ref: pinned, wantErr: "registry images.example.com is not declared"},
		{name: "no dialer", reads: registry.NewReads(nil, &lane.Lane{}), ref: pinned, wantErr: "dialer required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.reads.Transport(tt.ref)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Transport error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestReads_UndeclaredRegistryFailsEveryRead pins that the image, trust-root
// and base-SBOM reads each refuse a reference whose registry the lane does not
// declare, before any request.
func TestReads_UndeclaredRegistryFailsEveryRead(t *testing.T) {
	undeclared := registry.NewReads(testutil.StartDoTResolver(t, netip.MustParseAddr("127.0.0.1")), &lane.Lane{})
	ref := primitive.ImageRef("images.example.com/x@sha256:" + strings.Repeat("ab", 32))
	ctx := context.Background()
	tests := []struct {
		read func() error
		name string
	}{
		{name: "image", read: func() error {
			_, err := registry.FetchImage(ctx, ref, v1.Platform{OS: "linux", Architecture: "amd64"}, undeclared)
			return err
		}},
		{name: "trust root", read: func() error {
			_, err := registry.FetchTrustRoot(ctx, ref, undeclared)
			return err
		}},
		{name: "base SBOM referrers", read: func() error {
			_, err := registry.FetchBaseSBOMReferrers(ctx, ref, undeclared)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.read(); err == nil || !strings.Contains(err.Error(), "registry images.example.com is not declared") {
				t.Fatalf("read error = %v, want the undeclared registry named", err)
			}
		})
	}
}

// TestNewReads_DeployTargetIsARegistry pins that a deploy target's host counts
// as a declared registry without storages.
func TestNewReads_DeployTargetIsARegistry(t *testing.T) {
	dialer := testutil.StartDoTResolver(t, netip.MustParseAddr("127.0.0.1"))
	p := &lane.Lane{Steps: []lane.Step{{
		ID: "deploy",
		Deploy: &lane.DeploySpec{Method: lane.DeployRegistry{
			Type: "registry",
			Target: lane.DeployRegistryTarget{
				Type:       "https",
				Address:    endpoint.MustParseAuthority("registry.example.com"),
				Trust:      testutil.AnchorTrust(),
				Name:       "app",
				Credential: lane.RegistryCredential{Type: "bearer", Token: "registry-token"},
			},
		}},
	}}}
	if _, err := registry.NewReads(dialer, p).Transport(primitive.NewImageRef("registry.example.com/app@sha256:" + strings.Repeat("ab", 32))); err != nil {
		t.Fatalf("Transport for the deploy target: %v", err)
	}
}

// TestSystemTransports pins that strike verify reads through
// go-containerregistry's default transport.
func TestSystemTransports(t *testing.T) {
	rt, err := registry.SystemTransports{}.Transport(primitive.NewImageRef("images.example.com/x@sha256:" + strings.Repeat("ab", 32)))
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	if rt != remote.DefaultTransport {
		t.Errorf("Transport = %v, want remote.DefaultTransport", rt)
	}
}
