package registry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
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

// TestTargetTransports pins strike verify's transports under a registry
// token (ADR-041 amendment 2026-11-08): a read of the target authority
// carries the bearer and verifies the target against the declared anchor,
// so a target that presents another chain is refused; a read of any other
// registry is anonymous through go-containerregistry's default transport; an
// anchor of no known mode is refused when the transports are built.
func TestTargetTransports(t *testing.T) {
	const token = "header.payload.signature"
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	secret := lane.NewSecretString(token)

	get := func(src registry.TargetTransports) error {
		rt, err := src.Transport(primitive.NewImageRef(host + "/app@sha256:" + strings.Repeat("ab", 32)))
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/v2/", http.NoBody)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	pinned, err := registry.NewTargetTransports(host, endpoint.CertificateFromDER(srv.Certificate().Raw, endpoint.CertificateModeRootca), secret, registry.SystemTransports{})
	if err != nil {
		t.Fatalf("NewTargetTransports: %v", err)
	}
	if getErr := get(pinned); getErr != nil {
		t.Fatalf("read of the target: %v", getErr)
	}
	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "Bearer "+token {
		t.Errorf("Authorization on the target = %q, want the bearer once", got)
	}

	anchor, err := testutil.AnchorTrust().Parse()
	if err != nil {
		t.Fatalf("fixture anchor: %v", err)
	}
	wrong, err := registry.NewTargetTransports(host, endpoint.CertificateFromDER(anchor.Raw, endpoint.CertificateModeLeaf), secret, registry.SystemTransports{})
	if err != nil {
		t.Fatalf("NewTargetTransports: %v", err)
	}
	if getErr := get(wrong); getErr == nil {
		t.Error("a target that presents another certificate than the anchor was read")
	}

	rt, err := pinned.Transport(primitive.NewImageRef("other.example.com/root@sha256:" + strings.Repeat("cd", 32)))
	if err != nil {
		t.Fatalf("Transport of another registry: %v", err)
	}
	if rt != remote.DefaultTransport {
		t.Errorf("Transport of another registry = %v, want remote.DefaultTransport", rt)
	}
	if _, err := pinned.Transport(primitive.NewImageRef("Not A Reference")); err == nil {
		t.Error("Transport accepted a malformed reference")
	}
	if _, err := registry.NewTargetTransports(host, endpoint.Certificate{Cert: endpoint.CertificateFromDER(srv.Certificate().Raw, endpoint.CertificateModeRootca).Cert}, secret, registry.SystemTransports{}); err == nil {
		t.Error("NewTargetTransports accepted an anchor of no known mode")
	}
}
