package deploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

// TestNewRegistryTransport_RejectsNilDialer pins that the push transport
// refuses a missing lane dialer at construction, the way the capsule and
// mediator constructors do. Without the check a Deployer built without one
// fails inside the dial callback, long after the point that can report it.
func TestNewRegistryTransport_RejectsNilDialer(t *testing.T) {
	_, _, err := newRegistryTransport(DeployRegistryForTest().Target, nil, lane.SecretString{})
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
	_, _, err := pushSBOMPair(context.Background(), host+"/app", subject, registryClient{rt: srv.Client().Transport}, "image", fstest.MapFS{}, primitive.DigestFromHex(subjectHex))
	if err == nil {
		t.Fatal("expected an error for a registry without the referrers API, got nil")
	}
	for _, want := range []string{"registry " + host + " does not support the Referrers API", subject.Digest.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must contain %q", err, want)
		}
	}
}

// TestReadRegistryTokensChecksBeforeUse proves the fail-closed checks on the
// registry token at run start (ADR-058 D3, D4, amendment 2026-11-08): a token
// that cannot be read, is malformed, carries no lifetime, outlives the bound,
// carries an aud claim of neither form, or names the lane's oidc audience in
// either form of the claim is refused; a token minted for another audience is
// returned unchanged, keyed by the target authority.
func TestReadRegistryTokensChecksBeforeUse(t *testing.T) {
	tests := []struct {
		name    string
		source  lane.SecretSource
		token   string
		wantErr string
	}{
		{name: "unset variable", source: "env://STRIKE_TEST_UNSET_REGISTRY_TOKEN", wantErr: "registry token \"registry-token\""},
		{name: "malformed token", source: "env://REGISTRY_ID_TOKEN", token: "not-a-jwt", wantErr: "malformed identity token"},
		{name: "no lifetime", source: "env://REGISTRY_ID_TOKEN", token: fakeIDToken(`{"aud":"https://registry.example.com"}`), wantErr: "no valid iat and exp"},
		{name: "lifetime over bound", source: "env://REGISTRY_ID_TOKEN", token: fakeIDToken(`{"aud":"https://registry.example.com","iat":1000,"exp":1901}`), wantErr: "exceeds the 900s bound"},
		{name: "aud of neither form", source: "env://REGISTRY_ID_TOKEN", token: fakeIDToken(`{"aud":7,"iat":1000,"exp":1600}`), wantErr: "aud claim"},
		{name: "oidc audience", source: "env://REGISTRY_ID_TOKEN", token: fakeIDToken(`{"aud":"sigstore","iat":1000,"exp":1600}`), wantErr: "its audience contains the oidc audience \"sigstore\""},
		{name: "oidc audience among others", source: "env://REGISTRY_ID_TOKEN", token: fakeIDToken(`{"aud":["https://registry.example.com","sigstore"],"iat":1000,"exp":1600}`), wantErr: "its audience contains the oidc audience \"sigstore\""},
		{name: "registry audience", source: "env://REGISTRY_ID_TOKEN", token: fakeIDToken(`{"aud":["https://registry.example.com"],"iat":1000,"exp":1600}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("REGISTRY_ID_TOKEN", tt.token)
			method := DeployRegistryForTest()
			p := &lane.Lane{
				OIDC:    lane.OIDCConfig{Audience: "sigstore"},
				Secrets: map[primitive.Identifier]lane.SecretSource{"registry-token": tt.source},
				Steps:   []lane.Step{{ID: "deploy", Deploy: &lane.DeploySpec{Method: method}}},
			}
			tokens, err := ReadRegistryTokens(p, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ReadRegistryTokens: %v", err)
				}
				if got := tokens[string(method.Target.Address.Authority())]; got.Expose() != tt.token {
					t.Error("ReadRegistryTokens did not return the token it read under the target authority")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestCheckRegistryTokenWithoutAudience pins the check strike verify runs
// on a registry token in UC1, where no lane names an oidc audience: the
// lifetime bound still holds, and no audience is refused.
func TestCheckRegistryTokenWithoutAudience(t *testing.T) {
	sigstore := lane.NewSecretString(fakeIDToken(`{"aud":"sigstore","iat":1000,"exp":1600}`))
	if err := CheckRegistryToken(sigstore, ""); err != nil {
		t.Errorf("CheckRegistryToken without an oidc audience: %v", err)
	}
	long := lane.NewSecretString(fakeIDToken(`{"aud":"https://registry.example.com","iat":1000,"exp":1901}`))
	if err := CheckRegistryToken(long, ""); err == nil || !strings.Contains(err.Error(), "exceeds the 900s bound") {
		t.Errorf("err = %v, want the lifetime bound", err)
	}
}

// TestPushByDigestScrubsTheToken proves the log clause of ADR-058 D1: a
// registry that echoes the presented credential into its error body does not
// carry the token into the error the push returns; the redaction placeholder
// stands in its place.
func TestPushByDigestScrubsTheToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "":
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+r.Host+`/token",service="`+r.Host+`"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusForbidden)
			testutil.WriteBody(t, w, []byte(`{"errors":[{"code":"DENIED","message":"refused `+auth+`"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	const presented = "header.payload.signature"
	digest, err := empty.Image.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	token := lane.NewSecretString(presented)
	client := registryClient{rt: registry.CredentialTransport(srv.Client().Transport, srv.Listener.Addr().String(), token), token: token}
	err = pushByDigest(context.Background(), srv.Listener.Addr().String()+"/app", digest.String(), empty.Image, client)
	if err == nil {
		t.Fatal("expected the registry's refusal, got nil")
	}
	if strings.Contains(err.Error(), presented) {
		t.Errorf("push error carries the token: %v", err)
	}
	if !strings.Contains(err.Error(), "refused Bearer [REDACTED]") {
		t.Errorf("push error %q must carry the registry's message with the token redacted", err)
	}
}
