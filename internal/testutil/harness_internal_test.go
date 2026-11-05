package testutil

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHarnessDialer(t *testing.T) {
	ca, _ := testCA(t, "resolver", nil, nil)
	tests := []struct {
		name    string
		wantErr string
		cert    []byte
	}{
		{name: "pins the exported resolver certificate", cert: pemBytes("CERTIFICATE", ca.Raw)},
		{name: "resolver certificate missing", wantErr: "harness resolver certificate missing"},
		{name: "resolver certificate is not PEM", cert: []byte("x"), wantErr: "harness resolver anchor"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.cert != nil {
				pki := filepath.Join(dir, "pki")
				if err := os.Mkdir(pki, 0o700); err != nil {
					t.Fatalf("create pki dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(pki, "resolver.crt"), tc.cert, 0o600); err != nil {
					t.Fatalf("write resolver.crt: %v", err)
				}
			}
			d, err := HarnessDialer(dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || d == nil {
				t.Fatalf("HarnessDialer = %v, %v; want a dialer", d, err)
			}
		})
	}
}

func TestFindHarnessDir(t *testing.T) {
	withHarness := t.TempDir()
	nested := filepath.Join(withHarness, "a", "b")
	for _, d := range []string{nested, filepath.Join(withHarness, "test", "sigstore-local")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("create %s: %v", d, err)
		}
	}
	noHarness := t.TempDir()
	for _, root := range []string{withHarness, noHarness} {
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test\n"), 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
	}

	tests := []struct {
		name    string
		wd      string
		want    string
		wantErr string
	}{
		{name: "walks up to the module root", wd: nested, want: filepath.Join(withHarness, "test", "sigstore-local")},
		{name: "module without a harness", wd: noHarness, wantErr: "harness dir"},
		{name: "no module root", wd: "/", wantErr: "no go.mod at or above /"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(tc.wd)
			got, err := FindHarnessDir()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindHarnessDir: %v", err)
			}
			gotReal, err := filepath.EvalSymlinks(got)
			if err != nil {
				t.Fatalf("resolve %s: %v", got, err)
			}
			wantReal, err := filepath.EvalSymlinks(tc.want)
			if err != nil {
				t.Fatalf("resolve %s: %v", tc.want, err)
			}
			if gotReal != wantReal {
				t.Errorf("FindHarnessDir = %s, want %s", gotReal, wantReal)
			}
			if dir := HarnessDir(t); dir != got {
				t.Errorf("HarnessDir = %s, want %s", dir, got)
			}
		})
	}
}

func TestFetchIDToken(t *testing.T) {
	// The token endpoint answers by client id; any other deviation from the
	// harness password grant is a bad request.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/realms/test/protocol/openid-connect/token" ||
			r.FormValue("grant_type") != "password" || r.FormValue("username") != "tester" ||
			r.FormValue("password") != "tester" || r.FormValue("scope") != "openid" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.FormValue("client_id") {
		case "ok":
			WriteBody(t, w, []byte(`{"id_token":"token-for-ok"}`))
		case "garbled":
			WriteBody(t, w, []byte("{"))
		case "empty":
			WriteBody(t, w, []byte("{}"))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closed.Close()

	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, pemBytes("CERTIFICATE", srv.Certificate().Raw), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	issuer := srv.URL + "/realms/test"

	tests := []struct {
		name    string
		issuer  string
		client  string
		ca      string
		wantErr string
	}{
		{name: "password grant returns the id token", client: "ok"},
		{name: "anchor missing", client: "ok", ca: filepath.Join(t.TempDir(), "absent.crt"), wantErr: "keycloak tls config"},
		{name: "issuer does not parse", client: "ok", issuer: "https://\x7f", wantErr: "keycloak token request"},
		{name: "keycloak unreachable", client: "ok", issuer: closed.URL + "/realms/test", wantErr: "keycloak unreachable"},
		{name: "token endpoint refuses", client: "denied", wantErr: "keycloak token endpoint returned 401"},
		{name: "response is not JSON", client: "garbled", wantErr: "keycloak token decode"},
		{name: "response has no id_token", client: "empty", wantErr: "keycloak token response has no id_token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iss, ca := tc.issuer, tc.ca
			if iss == "" {
				iss = issuer
			}
			if ca == "" {
				ca = caPath
			}
			token, err := FetchIDToken(t.Context(), iss, tc.client, ca)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchIDToken: %v", err)
			}
			if token != "token-for-ok" {
				t.Errorf("FetchIDToken = %q, want token-for-ok", token)
			}
			if minted := MintIDToken(t, iss, tc.client, ca); minted != token {
				t.Errorf("MintIDToken = %q, want %q", minted, token)
			}
		})
	}
}
