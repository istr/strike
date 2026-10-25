package executor_test

import (
	"context"
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

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// baseEntry is one platform image of a pushed base index.
type baseEntry struct {
	content  string
	platform v1.Platform
}

// pushBaseIndex pushes an index of one-layer images, in the order given, into
// an in-process registry, and returns the reference by index digest and the
// manifest digest of every entry.
func pushBaseIndex(t *testing.T, entries []baseEntry) (primitive.ImageRef, []v1.Hash) {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	digests := make([]v1.Hash, 0, len(entries))
	for i := range entries {
		img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
		img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
		img, err = mutate.AppendLayers(img, static.NewLayer([]byte(entries[i].content), types.OCILayer))
		if err != nil {
			t.Fatalf("append layer: %v", err)
		}
		d, dErr := img.Digest()
		if dErr != nil {
			t.Fatalf("manifest digest: %v", dErr)
		}
		digests = append(digests, d)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &entries[i].platform},
		})
	}
	repo := "localhost:" + u.Port() + "/t/base"
	tag, err := name.ParseReference(repo + ":pushed")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if wErr := remote.WriteIndex(tag, idx); wErr != nil {
		t.Fatalf("push index: %v", wErr)
	}
	indexDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("index digest: %v", err)
	}
	return primitive.ImageRef(repo + "@" + indexDigest.String()), digests
}

// TestPack_BaseResolvesToTheRequestedPlatform pins that a pack base declared
// by an index digest is the entry of the requested platform, selected by the
// rule step-image materialization uses: not the first entry, and not
// go-containerregistry's default platform, linux/amd64, which this index
// lists first. A spec with no files and no config assembles the base
// unchanged, so the result digest is the selected entry's manifest digest.
func TestPack_BaseResolvesToTheRequestedPlatform(t *testing.T) {
	ref, digests := pushBaseIndex(t, []baseEntry{
		{content: "amd64 base", platform: v1.Platform{OS: "linux", Architecture: "amd64"}},
		{content: "arm64 base", platform: v1.Platform{OS: "linux", Architecture: "arm64"}},
		{content: "arm v6 base", platform: v1.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}},
		{content: "arm v7 base", platform: v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}},
	})
	tests := []struct {
		name      string
		wantErr   string
		platform  v1.Platform
		wantEntry int
	}{
		{
			name:      "arm64 although amd64 is listed first",
			platform:  v1.Platform{OS: "linux", Architecture: "arm64"},
			wantEntry: 1,
		},
		{
			name:      "amd64",
			platform:  v1.Platform{OS: "linux", Architecture: "amd64"},
			wantEntry: 0,
		},
		{
			name:      "the variant decides between two arm entries",
			platform:  v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
			wantEntry: 3,
		},
		{
			name:     "no entry for the platform",
			platform: v1.Platform{OS: "linux", Architecture: "s390x"},
			wantErr:  "index has no manifest for linux/s390x",
		},
		{
			name:    "an empty platform matches no entry",
			wantErr: "index has no manifest for /",
		},
		{
			name:     "two entries the variant does not decide",
			platform: v1.Platform{OS: "linux", Architecture: "arm"},
			wantErr:  "does not decide",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := executor.Pack(context.Background(), executor.PackOpts{
				Spec:     &lane.PackSpec{Base: ref, Files: []lane.PackFile{}},
				Platform: tt.platform,
			})
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Pack() = nil error, want an error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Pack() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			want := digests[tt.wantEntry].String()
			if result.Digest.String() != want {
				t.Errorf("assembled digest = %s, want entry %d, %s", result.Digest, tt.wantEntry, want)
			}
		})
	}
}
