package registry_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// TestCredentialTransport pins the three rules of the credential transport
// (ADR-058 amendment 2026-11-08): the bearer rides a request to the declared
// authority; a redirect, even on the same host, is refused before the
// redirected request is sent; a request to another host is refused before
// it is dialed.
func TestCredentialTransport(t *testing.T) {
	const token = "header.payload.signature"
	var (
		mu   sync.Mutex
		seen = map[string]string{}
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	authority := srv.Listener.Addr().String()
	client := &http.Client{Transport: registry.CredentialTransport(srv.Client().Transport, authority, lane.NewSecretString(token))}

	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{name: "declared authority", url: "https://" + authority + "/v2/"},
		{name: "redirect on the same host", url: "https://" + authority + "/redirect", wantErr: "redirect to " + authority + " refused; a request carrying the declared credential is never redirected"},
		{name: "another host", url: "https://other.example/v2/", wantErr: "request to other.example refused; the declared credential is presented to its own registry only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tt.url, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := client.Do(req)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Do error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if cErr := resp.Body.Close(); cErr != nil {
				t.Fatalf("close body: %v", cErr)
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	if got := seen["/v2/"]; got != "Bearer "+token {
		t.Errorf("declared authority saw Authorization %q, want the bearer", got)
	}
	if got := seen["/redirect"]; got != "Bearer "+token {
		t.Errorf("redirecting request saw Authorization %q, want the bearer", got)
	}
	if _, sent := seen["/target"]; sent {
		t.Error("the redirected request reached the server")
	}
}
