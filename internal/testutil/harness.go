package testutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
// test/sigstore-local. A missing directory is fatal with the opt-out hint: the
// harness is a prerequisite, not a skip condition (docs/DEVELOPMENT.md section
// 2.5). The hint is why this wrapper exists at all: it is the only caller that
// can act on it.
func HarnessDir(t *testing.T) string {
	t.Helper()
	dir, err := FindHarnessDir()
	if err != nil {
		t.Fatalf("%v; set STRIKE_INTEGRATION=0 to skip integration tests", err)
	}
	return dir
}

// FindHarnessDir resolves test/sigstore-local from the module root and returns
// bare errors. Non-test callers -- the golden generator runs as a standalone
// command -- have no working-directory contract, so the root is found by
// walking up rather than assumed.
func FindHarnessDir() (string, error) {
	root, err := ModuleRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "test", "sigstore-local")
	if _, statErr := os.Stat(dir); statErr != nil {
		return "", fmt.Errorf("harness dir %s missing: %w", dir, statErr)
	}
	return dir, nil
}

// ModuleRoot walks up from the working directory to the directory holding
// go.mod, so a caller is independent of where it was started.
func ModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod at or above %s", dir)
		}
		dir = parent
	}
}

// MintIDToken obtains an OIDC id_token from the harness Keycloak, mirroring
// the harness Makefile token target: password grant for user tester with
// client sigstore, TLS pinned to the exported caddy root at caCertPath. Any
// failure is fatal with the opt-out hint -- the harness is a prerequisite,
// not a skip condition.
func MintIDToken(t *testing.T, issuer, caCertPath string) string {
	t.Helper()
	token, err := FetchIDToken(t.Context(), issuer, caCertPath)
	if err != nil {
		t.Fatalf("%v; set STRIKE_INTEGRATION=0 to skip integration tests", err)
	}
	return token
}

// FetchIDToken performs the Keycloak password grant and returns the id_token,
// with bare errors. The STRIKE_INTEGRATION hint lives in MintIDToken, not here:
// a standalone command cannot act on it, and a wrong hint is worse than none.
func FetchIDToken(ctx context.Context, issuer, caCertPath string) (string, error) {
	cfg, err := transport.BuildTLSConfig(endpoint.CABundle{Type: "caBundle", Path: primitive.AbsPath(caCertPath)})
	if err != nil {
		return "", fmt.Errorf("keycloak tls config: %w", err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("keycloak token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak unreachable: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close keycloak token response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak token endpoint returned %d", resp.StatusCode)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("keycloak token decode: %w", err)
	}
	if body.IDToken == "" {
		return "", errors.New("keycloak token response has no id_token")
	}
	return body.IDToken, nil
}
