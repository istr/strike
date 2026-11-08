package registry_test

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

// emptyReferrers is a referrers listing that holds no referrer.
const emptyReferrers = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`

// servedCase is one case of TestConfirmServed: how the registry serves late
// once armed, what the fake wait answers, and what the confirmation must do.
type servedCase struct {
	waitErr     error
	name        string
	listBody    string
	wantErr     []string
	wantWaits   []clock.Duration
	listStatus  int
	headStatus  int
	lateLists   int32
	lateHeads   int32
	wantMissing bool
}

// lateServer serves an in-memory registry with the referrers API on a
// localhost port and returns its host and the switch that arms it. Armed, it
// serves as tc says: a non-zero listStatus or headStatus answers every
// referrers listing or manifest HEAD with that status, and a listBody answers
// every listing with that body; otherwise the first lateLists listings hold
// no referrer and the first lateHeads manifest HEADs answer 404.
func lateServer(t *testing.T, tc servedCase) (string, *atomic.Bool) {
	t.Helper()
	inner := regtest.Registry(t, true)
	armed := &atomic.Bool{}
	var lists, heads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listing := r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/")
		head := r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/")
		switch {
		case !armed.Load():
			// Not armed: the setup pushes and reads as usual.
		case listing && tc.listStatus != 0:
			w.WriteHeader(tc.listStatus)
			return
		case head && tc.headStatus != 0:
			w.WriteHeader(tc.headStatus)
			return
		case listing && tc.listBody != "":
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			testutil.WriteBody(t, w, []byte(tc.listBody))
			return
		case listing && lists.Add(1) <= tc.lateLists:
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			testutil.WriteBody(t, w, []byte(emptyReferrers))
			return
		case head && heads.Add(1) <= tc.lateHeads:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return "localhost:" + u.Port(), armed
}

// pushSBOMReferrer pushes a CycloneDX document as an OCI referrer of subject
// into repo and returns its descriptor.
func pushSBOMReferrer(t *testing.T, repo string, subject v1.Descriptor) v1.Descriptor {
	t.Helper()
	art, err := registry.ArtifactImage([]byte(`{"bomFormat":"CycloneDX"}`), "application/vnd.cyclonedx+json", subject, nil)
	if err != nil {
		t.Fatalf("sbom artifact: %v", err)
	}
	desc, err := partial.Descriptor(art)
	if err != nil {
		t.Fatalf("sbom descriptor: %v", err)
	}
	ref, err := name.NewDigest(repo + "@" + desc.Digest.String())
	if err != nil {
		t.Fatalf("sbom reference: %v", err)
	}
	if writeErr := remote.Write(ref, art, remote.WithReferrersTagFallback(false)); writeErr != nil {
		t.Fatalf("push sbom: %v", writeErr)
	}
	return *desc
}

// TestConfirmServed pins the read-after-write (ADR-051 amendment
// 2026-11-08) over a statement bundle and an SBOM referrer of one subject:
// what is served at once needs no wait; a listing or a HEAD served late is
// read again after a wait of one second that doubles; what is never served
// fails after waits that add up to one minute, naming the registry, the
// subject and every digest not served; a refusal, a registry without the
// referrers API, a malformed listing and an interrupted wait end the
// confirmation at once. The wait is a fake that records what it is asked to
// wait, so no case waits.
func TestConfirmServed(t *testing.T) {
	full := []clock.Duration{clock.Second, 2 * clock.Second, 4 * clock.Second, 8 * clock.Second, 16 * clock.Second, 29 * clock.Second}
	tests := []servedCase{
		{name: "served at once"},
		{name: "listing late", lateLists: 3, wantWaits: full[:2]},
		{name: "head late", lateHeads: 1, wantWaits: full[:1]},
		{name: "never served", lateLists: math.MaxInt32, wantWaits: full, wantErr: []string{"not served after 1m0s"}, wantMissing: true},
		{name: "refused", headStatus: http.StatusForbidden, wantErr: []string{"403 Forbidden"}},
		{name: "no referrers API", listStatus: http.StatusNotFound, wantErr: []string{"does not support the Referrers API"}},
		{name: "listing malformed", listBody: "{", wantErr: []string{"referrers index"}},
		{name: "wait interrupted", lateLists: math.MaxInt32, waitErr: context.Canceled, wantWaits: full[:1], wantErr: []string{"context canceled"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, armed := lateServer(t, tc)
			subject := pushSubject(t, host+"/app:v1")
			bundles, err := registry.AttachStatementBundles(context.Background(), host+"/app:v1", subject, []registry.StatementBundle{
				{Statement: record.TrustLayerSealed, Bundle: []byte(`{"bundle":"sealed"}`)},
			})
			if err != nil {
				t.Fatalf("AttachStatementBundles: %v", err)
			}
			referrers := append(bundles, pushSBOMReferrer(t, host+"/app", subject))
			armed.Store(true)
			var waits []clock.Duration
			wait := func(_ context.Context, d clock.Duration) error {
				waits = append(waits, d)
				return tc.waitErr
			}
			err = registry.ConfirmServed(context.Background(), http.DefaultTransport, host+"/app", subject.Digest, referrers, wait)
			if !slices.Equal(waits, tc.wantWaits) {
				t.Errorf("waits = %v, want %v", waits, tc.wantWaits)
			}
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("ConfirmServed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ConfirmServed succeeded, want an error")
			}
			want := append([]string{"registry " + host + ": subject " + subject.Digest.String()}, tc.wantErr...)
			if tc.wantMissing {
				for _, d := range referrers {
					want = append(want, d.Digest.String())
				}
			}
			for _, w := range want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q must contain %q", err, w)
				}
			}
		})
	}
}

// TestConfirmServedRejectsMalformedRepository pins that a repository name
// go-containerregistry does not parse fails before any read and any wait.
func TestConfirmServedRejectsMalformedRepository(t *testing.T) {
	err := registry.ConfirmServed(context.Background(), http.DefaultTransport, "Not/A/Repository", v1.Hash{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "read-after-write Not/A/Repository") {
		t.Fatalf("err = %v, want a read-after-write error naming the repository", err)
	}
}
