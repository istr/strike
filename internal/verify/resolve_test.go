package verify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ggcrmutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/lane"
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

func TestResolveOverride(t *testing.T) {
	golden := readTrustRootGolden(t)
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, golden, 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	tm, err := verify.ResolveTrustedMaterial(context.Background(), path, lane.Keyless{})
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
	golden := readTrustRootGolden(t)
	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host := "localhost:" + u.Port()
	ref := host + "/trust:v1"

	img := ggcrmutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err = ggcrmutate.AppendLayers(img, static.NewLayer(golden, types.OCILayer))
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

	k := lane.Keyless{TrustRootRef: lane.ImageRef(host + "/trust@" + digest.String())}
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
	golden := readTrustRootGolden(t)
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, golden, 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	// A deliberately invalid inline replica: if the override did not short-
	// circuit, marshalling and parsing this would fail.
	k := lane.Keyless{TrustRoot: &lane.TrustedRootReplica{}}
	tm, err := verify.ResolveTrustedMaterial(context.Background(), path, k)
	if err != nil {
		t.Fatalf("override should short-circuit invalid inline: %v", err)
	}
	if tm == nil {
		t.Fatal("trusted material is nil")
	}
}
