package verify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ggcrmutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/verify"
)

func readTrustRootGolden(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/golden/trusted_root.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	return data
}

// pushGoldenTrustRoot publishes the golden trusted_root.json as a single-layer
// OCI image to a fresh in-memory registry and returns its digest-pinned
// reference. Both the override and the lane-declared ref resolve such a ref via
// registry.FetchTrustRoot, so no host-local file is involved.
func pushGoldenTrustRoot(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host := "localhost:" + u.Port()
	img := ggcrmutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err = ggcrmutate.AppendLayers(img, static.NewLayer(readTrustRootGolden(t), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	nameRef, err := name.ParseReference(host + "/trust:v1")
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
	return host + "/trust@" + digest.String()
}

func TestResolveOverride(t *testing.T) {
	tm, err := verify.ResolveTrustedMaterial(context.Background(), primitive.NewImageRef(pushGoldenTrustRoot(t)), lane.Keyless{})
	if err != nil {
		t.Fatalf("ResolveTrustedMaterial: %v", err)
	}
	if tm == nil {
		t.Fatal("trusted material is nil")
	}
}

func TestResolveInlineRoundTrip(t *testing.T) {
	var replica lane.TrustedRootReplica
	if err := json.Unmarshal(readTrustRootGolden(t), &replica); err != nil {
		t.Fatalf("unmarshal golden into replica: %v", err)
	}
	tm, err := verify.ResolveTrustedMaterial(context.Background(), "", lane.Keyless{TrustRoot: &replica})
	if err != nil {
		t.Fatalf("inline round-trip: %v", err)
	}
	if tm == nil {
		t.Fatal("trusted material is nil")
	}
}

func TestResolveRef(t *testing.T) {
	k := lane.Keyless{TrustRootRef: primitive.ImageRef(pushGoldenTrustRoot(t))}
	tm, err := verify.ResolveTrustedMaterial(context.Background(), "", k)
	if err != nil {
		t.Fatalf("ResolveTrustedMaterial: %v", err)
	}
	if tm == nil {
		t.Fatal("trusted material is nil")
	}
}

func TestResolveNoDefault(t *testing.T) {
	_, err := verify.ResolveTrustedMaterial(context.Background(), "", lane.Keyless{})
	if !errors.Is(err, verify.ErrNoTrustRoot) {
		t.Fatalf("err = %v, want ErrNoTrustRoot", err)
	}
}

func TestResolvePrecedenceOverrideShortCircuits(t *testing.T) {
	// A deliberately invalid inline replica: if the override did not short-
	// circuit, marshalling and parsing this would fail.
	k := lane.Keyless{TrustRoot: &lane.TrustedRootReplica{}}
	tm, err := verify.ResolveTrustedMaterial(context.Background(), primitive.NewImageRef(pushGoldenTrustRoot(t)), k)
	if err != nil {
		t.Fatalf("override should short-circuit invalid inline: %v", err)
	}
	if tm == nil {
		t.Fatal("trusted material is nil")
	}
}
