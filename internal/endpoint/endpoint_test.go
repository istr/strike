package endpoint_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/testutil"
)

// TestUnmarshalEndpoint exercises the discriminator dispatch of the
// hand-written endpoint union: each concrete branch decodes to its type, and
// a missing, empty, unknown or malformed entry surfaces an error.
func TestUnmarshalEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		check   func(t *testing.T, e endpoint.Endpoint)
		wantErr string
	}{
		{
			name: "https with absent mode",
			input: `{
				"type": "https",
				"host": "example.com",
				"trust": {"cert": "@anchor@"}
			}`,
			check: func(t *testing.T, e endpoint.Endpoint) {
				h, ok := e.(endpoint.TLS)
				if !ok {
					t.Fatalf("type = %T, want endpoint.TLS", e)
				}
				if h.Address.Authority() != "example.com" {
					t.Errorf("Host = %q, want example.com", h.Address.Authority())
				}
				// The default mode is a CUE default arm that Parse materializes
				// before decoding; this decoder alone leaves an absent mode empty.
				if h.Trust.Mode != "" {
					t.Errorf("Trust.Mode = %q, want empty before schema defaults apply", h.Trust.Mode)
				}
				if h.Trust.Cert == "" {
					t.Error("Trust.Cert is empty")
				}
			},
		},
		{
			name: "https with leaf mode",
			input: `{
				"type": "https",
				"host": "internal.example",
				"trust": {"mode": "leaf", "cert": "@anchor@"}
			}`,
			check: func(t *testing.T, e endpoint.Endpoint) {
				h, ok := e.(endpoint.TLS)
				if !ok {
					t.Fatalf("type = %T, want endpoint.TLS", e)
				}
				if h.Trust.Mode != endpoint.CertificateModeLeaf {
					t.Errorf("Trust.Mode = %q, want leaf", h.Trust.Mode)
				}
			},
		},
		{
			name: "ssh with known_hosts",
			input: `{
				"type": "ssh",
				"host": "git.example",
				"knownHosts": [
					{"keyType": "ssh-ed25519", "key": "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}
				]
			}`,
			check: func(t *testing.T, e endpoint.Endpoint) {
				s, ok := e.(endpoint.SSH)
				if !ok {
					t.Fatalf("type = %T, want endpoint.SSH", e)
				}
				if len(s.KnownHosts) != 1 {
					t.Errorf("KnownHosts len = %d, want 1", len(s.KnownHosts))
				}
				if s.KnownHosts[0].KeyType != "ssh-ed25519" {
					t.Errorf("KnownHosts[0].KeyType = %q, want ssh-ed25519", s.KnownHosts[0].KeyType)
				}
			},
		},
		{
			name:    "oci rejected",
			input:   `{"type": "oci", "registry": "registry.example.com"}`,
			wantErr: "unknown endpoint type",
		},
		{
			name:    "unknown type",
			input:   `{"type": "ftp", "host": "example.com"}`,
			wantErr: "unknown endpoint type",
		},
		{
			name:    "missing type",
			input:   `{"host": "example.com"}`,
			wantErr: "endpoint missing type discriminator",
		},
		{
			name:    "https missing trust",
			input:   `{"type": "https", "host": "example.com"}`,
			wantErr: "https endpoint: trust required",
		},
		{
			name:    "null entry",
			input:   `null`,
			wantErr: "endpoint entry missing",
		},
		{
			name:    "empty entry",
			input:   ``,
			wantErr: "endpoint entry missing",
		},
		{
			name:    "type not a string",
			input:   `{"type": 5}`,
			wantErr: "endpoint: ",
		},
		{
			name:    "https trust not an object",
			input:   `{"type": "https", "host": "example.com", "trust": 5}`,
			wantErr: "decode https endpoint",
		},
		{
			name:    "https empty host",
			input:   `{"type": "https", "host": "", "trust": {"cert": "@anchor@"}}`,
			wantErr: "https endpoint: invalid authority",
		},
		{
			name:    "ssh known hosts not a list",
			input:   `{"type": "ssh", "host": "git.example", "knownHosts": 5}`,
			wantErr: "decode ssh endpoint",
		},
		{
			name:    "ssh empty host",
			input:   `{"type": "ssh", "host": "", "knownHosts": []}`,
			wantErr: "ssh endpoint: invalid authority",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.ReplaceAll(tc.input, "@anchor@", testutil.AnchorCertB64)
			e, err := endpoint.UnmarshalEndpoint([]byte(input))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalEndpoint: %v", err)
			}
			tc.check(t, e)
		})
	}
}

// TestServerTLSJSON exercises the codec of the server shape a field holds when
// its role fixes the carriage: it decodes host and trust without a type
// discriminator, rejects a missing trust, a malformed trust and an empty host,
// and encodes back to host and trust without a type.
func TestServerTLSJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:  "host and trust",
			input: `{"host": "registry.example.com:5000", "trust": {"cert": "@anchor@"}}`,
		},
		{
			name:    "missing trust",
			input:   `{"host": "registry.example.com"}`,
			wantErr: "https endpoint: trust required",
		},
		{
			name:    "trust not an object",
			input:   `{"host": "registry.example.com", "trust": 5}`,
			wantErr: "decode https endpoint",
		},
		{
			name:    "empty host",
			input:   `{"host": "", "trust": {"cert": "@anchor@"}}`,
			wantErr: "https endpoint: invalid authority",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.ReplaceAll(tc.input, "@anchor@", testutil.AnchorCertB64)
			var s endpoint.ServerTLS
			err := json.Unmarshal([]byte(input), &s)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if s.Address.Authority() != "registry.example.com:5000" {
				t.Errorf("host = %q, want registry.example.com:5000", s.Address.Authority())
			}
			out, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if strings.Contains(string(out), `"type"`) {
				t.Errorf("wire form = %s, want no type discriminator", out)
			}
			var back endpoint.ServerTLS
			if err = json.Unmarshal(out, &back); err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if back.Address.Authority() != s.Address.Authority() || back.Trust != s.Trust {
				t.Errorf("round trip = %+v, want %+v", back, s)
			}
		})
	}
}
