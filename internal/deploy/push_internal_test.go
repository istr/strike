package deploy

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry/regtest"
)

// TestNewRegistryTransport_RejectsNilDialer pins that the push transport
// refuses a missing lane dialer at construction, the way the capsule and
// mediator constructors do. Without the check a Deployer built without one
// fails inside the dial callback, long after the point that can report it.
func TestNewRegistryTransport_RejectsNilDialer(t *testing.T) {
	_, _, err := newRegistryTransport(DeployRegistryForTest().Target, nil)
	if err == nil {
		t.Fatal("expected an error for a nil dialer, got nil")
	}
	if !strings.Contains(err.Error(), "dialer required") {
		t.Errorf("error %q must report the missing dialer", err)
	}
}

// TestPushSBOMPairRefusesTagFallback pins that an SBOM referrer push to a
// registry without the referrers API fails with an error naming the registry
// and the subject digest, instead of maintaining a referrers fallback tag.
func TestPushSBOMPairRefusesTagFallback(t *testing.T) {
	srv := httptest.NewTLSServer(regtest.Registry(t, false))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	subjectHex := strings.Repeat("ab", 32)
	subject := v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    v1.Hash{Algorithm: "sha256", Hex: subjectHex},
		Size:      2,
	}
	_, err := pushSBOMPair(context.Background(), host+"/app", subject, srv.Client().Transport, "image", fstest.MapFS{}, primitive.DigestFromHex(subjectHex))
	if err == nil {
		t.Fatal("expected an error for a registry without the referrers API, got nil")
	}
	for _, want := range []string{"registry " + host + " does not support the Referrers API", subject.Digest.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must contain %q", err, want)
		}
	}
}
