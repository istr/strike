package endpoint_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/istr/strike/internal/endpoint"
)

func TestParseAuthority(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantHost string
		wantPort int // 0 means no port
		wantErr  bool
	}{
		{"bare host", "git.example.com", "git.example.com", 0, false},
		{"host with port", "git.example.com:2222", "git.example.com", 2222, false},
		{"ipv4", "1.2.3.4", "1.2.3.4", 0, false},
		{"ipv4 with port", "1.2.3.4:443", "1.2.3.4", 443, false},
		{"min port", "h:1", "h", 1, false},
		{"max port", "h:65535", "h", 65535, false},
		{"empty", "", "", 0, true},
		{"empty host", ":443", "", 0, true},
		{"port zero", "h:0", "", 0, true},
		{"port too large", "h:65536", "", 0, true},
		{"port not a number", "h:abc", "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := endpoint.ParseAuthority(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAuthority(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAuthority(%q): %v", tc.in, err)
			}
			if got.Host.String() != tc.wantHost {
				t.Errorf("host = %q, want %q", got.Host, tc.wantHost)
			}
			if tc.wantPort == 0 {
				if got.Port != nil {
					t.Errorf("port = %d, want nil", *got.Port)
				}
			} else {
				if got.Port == nil {
					t.Fatalf("port = nil, want %d", tc.wantPort)
				}
				if int(*got.Port) != tc.wantPort {
					t.Errorf("port = %d, want %d", *got.Port, tc.wantPort)
				}
			}
			if got.Path != nil {
				t.Errorf("path = %q, want nil", *got.Path)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantHost string
		wantPath string // "" means no path
		wantPort int
		wantErr  bool
	}{
		{"host only", "https://fulcio.example", "fulcio.example", "", 0, false},
		{"host and port", "https://fulcio.example:5555", "fulcio.example", "", 5555, false},
		{"host and path", "https://rekor.example/api/v2", "rekor.example", "/api/v2", 0, false},
		{"host port path", "https://rekor.example:5555/api/v2", "rekor.example", "/api/v2", 5555, false},
		{"trailing slash", "https://tsa.example/", "tsa.example", "/", 0, false},
		{"no scheme", "fulcio.example", "", "", 0, true},
		{"http scheme", "http://fulcio.example", "", "", 0, true},
		{"empty host", "https://:5555", "", "", 0, true},
		{"bad port", "https://h:abc/x", "", "", 0, true},
		{"query", "https://idp.example.com/x?a=b", "", "", 0, true},
		{"empty query", "https://idp.example.com?", "", "", 0, true},
		{"fragment", "https://idp.example.com/#f", "", "", 0, true},
		{"leading zero port", "https://idp.example.com:0443", "", "", 0, true},
		{"signed port", "https://idp.example.com:+443", "", "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := endpoint.ParseURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseURL(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", tc.in, err)
			}
			if got.Host.String() != tc.wantHost {
				t.Errorf("host = %q, want %q", got.Host, tc.wantHost)
			}
			if tc.wantPort == 0 {
				if got.Port != nil {
					t.Errorf("port = %d, want nil", *got.Port)
				}
			} else if got.Port == nil || int(*got.Port) != tc.wantPort {
				t.Errorf("port = %v, want %d", got.Port, tc.wantPort)
			}
			if tc.wantPath == "" {
				if got.Path != nil {
					t.Errorf("path = %q, want nil", *got.Path)
				}
			} else if got.Path == nil || got.Path.String() != tc.wantPath {
				t.Errorf("path = %v, want %q", got.Path, tc.wantPath)
			}
		})
	}
}

func TestAuthorityRoundTrip(t *testing.T) {
	for _, s := range []string{"git.example.com", "git.example.com:2222", "1.2.3.4:443"} {
		t.Run(s, func(t *testing.T) {
			a, err := endpoint.ParseAuthority(s)
			if err != nil {
				t.Fatalf("ParseAuthority(%q): %v", s, err)
			}
			if got := string(a.Authority()); got != s {
				t.Errorf("round-trip Authority() = %q, want %q", got, s)
			}
		})
	}
}

func TestBracketedHostPort(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare host", "git.example.com", "git.example.com"},
		{"host with port", "git.example.com:2222", "[git.example.com]:2222"},
		{"ipv4 bare", "1.2.3.4", "1.2.3.4"},
		{"ipv4 with port", "1.2.3.4:443", "[1.2.3.4]:443"},
		{"min port", "h:1", "[h]:1"},
		{"max port", "h:65535", "[h]:65535"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := endpoint.ParseAuthority(tc.in)
			if err != nil {
				t.Fatalf("ParseAuthority(%q): %v", tc.in, err)
			}
			if got := a.BracketedHostPort(); got != tc.want {
				t.Errorf("BracketedHostPort() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBracketedHostPortIgnoresPath(t *testing.T) {
	a, err := endpoint.ParseURL("https://rekor.example:5555/api/v2")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	const want = "[rekor.example]:5555"
	if got := a.BracketedHostPort(); got != want {
		t.Errorf("BracketedHostPort() = %q, want %q", got, want)
	}
}

func TestURLRoundTrip(t *testing.T) {
	for _, s := range []string{
		"https://fulcio.example",
		"https://fulcio.example:5555",
		"https://rekor.example/api/v2",
		"https://rekor.example:5555/api/v2",
		"https://tsa.example/",
	} {
		t.Run(s, func(t *testing.T) {
			a, err := endpoint.ParseURL(s)
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", s, err)
			}
			if got := a.URL(); got != s {
				t.Errorf("round-trip URL() = %q, want %q", got, s)
			}
		})
	}
}

// TestAddressIssuerWireForm is the round-trip property over every OIDC and
// base-SBOM-signer issuer the tree's fixtures declare: ParseURL, String,
// MarshalJSON, and UnmarshalJSON reproduce the input string byte for byte, so
// an issuer field typed as Address emits exactly the bytes a plain string
// field emits.
func TestAddressIssuerWireForm(t *testing.T) {
	for _, s := range []string{
		"https://accounts.google.com",
		"https://idp.example.com",
		"https://issuer.example",
		"https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore",
		"https://wrong.example",
	} {
		t.Run(s, func(t *testing.T) {
			a, err := endpoint.ParseURL(s)
			if err != nil {
				t.Fatalf("ParseURL(%q): %v", s, err)
			}
			if got := a.String(); got != s {
				t.Errorf("String() = %q, want %q", got, s)
			}
			got, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("marshal Address: %v", err)
			}
			want, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("marshal string: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MarshalJSON = %s, want %s", got, want)
			}
			var back endpoint.Address
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("UnmarshalJSON(%s): %v", got, err)
			}
			if back.URL() != s {
				t.Errorf("UnmarshalJSON round trip = %q, want %q", back.URL(), s)
			}
		})
	}
}

func TestAddressUnmarshalJSONRejects(t *testing.T) {
	for _, in := range []string{
		`42`,
		`null`,
		`"http://idp.example.com"`,
		`"https://idp.example.com?a=b"`,
	} {
		t.Run(in, func(t *testing.T) {
			var a endpoint.Address
			if err := json.Unmarshal([]byte(in), &a); err == nil {
				t.Fatalf("Unmarshal(%s) = %+v, want error", in, a)
			}
		})
	}
}
