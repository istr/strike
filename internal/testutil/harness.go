package testutil

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// harnessHTTPTimeout bounds one Keycloak token round trip.
const harnessHTTPTimeout = 30 * clock.Second

// HarnessDir returns the absolute path of the local sigstore harness,
// test/sigstore-local. Callers are test packages two levels below the
// repository root, so the path is resolved from the test's working directory.
// A missing directory is fatal with the opt-out hint: the harness is a
// prerequisite, not a skip condition (docs/DEVELOPMENT.md section 2.5).
func HarnessDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "test", "sigstore-local"))
	if err != nil {
		t.Fatalf("resolve harness dir: %v", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("harness dir %s missing (%v); set STRIKE_INTEGRATION=0 to skip integration tests", dir, statErr)
	}
	return dir
}

// MintIDToken obtains an OIDC id_token from the harness Keycloak, mirroring
// the harness Makefile token target: password grant for user tester with
// client sigstore, TLS pinned to the exported caddy root at caCertPath. Any
// failure is fatal with the opt-out hint -- the harness is a prerequisite,
// not a skip condition.
func MintIDToken(t *testing.T, issuer, caCertPath string) string {
	t.Helper()
	cfg, err := transport.BuildTLSConfig(endpoint.CABundle{Type: "caBundle", Path: primitive.AbsPath(caCertPath)})
	if err != nil {
		t.Fatalf("keycloak tls config: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   harnessHTTPTimeout,
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"sigstore"},
		"username":   {"tester"},
		"password":   {"tester"},
		"scope":      {"openid"},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("keycloak token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("keycloak unreachable (%v); set STRIKE_INTEGRATION=0 to skip integration tests", err)
	}
	defer CloseLog(t, resp.Body, "keycloak token response")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keycloak token endpoint returned %d; set STRIKE_INTEGRATION=0 to skip integration tests", resp.StatusCode)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("keycloak token decode: %v", err)
	}
	if body.IDToken == "" {
		t.Fatal("keycloak token response has no id_token")
	}
	return body.IDToken
}
