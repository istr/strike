package endpoint_test

import (
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
			if string(got.Host) != tc.wantHost {
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
			if string(got.Host) != tc.wantHost {
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
			} else if got.Path == nil || string(*got.Path) != tc.wantPath {
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
			if got := a.Authority(); got != s {
				t.Errorf("round-trip Authority() = %q, want %q", got, s)
			}
		})
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
