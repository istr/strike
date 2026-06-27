package endpoint_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/endpoint"
)

// TestUnmarshalEngine exercises the discriminator dispatch of the
// hand-written engine-connection union: each concrete branch decodes to its
// type, and the missing/empty/unknown discriminator cases surface an error.
// Mirrors lane.UnmarshalPeer's table-driven dispatch test.
func TestUnmarshalEngine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		check   func(t *testing.T, c endpoint.Engine)
		wantErr string
	}{
		{
			name:  "unix",
			input: `{"type": "unix"}`,
			check: func(t *testing.T, c endpoint.Engine) {
				u, ok := c.(endpoint.EngineUnix)
				if !ok {
					t.Fatalf("type = %T, want EngineUnix", c)
				}
				if u.ConnectionType() != "unix" {
					t.Errorf("ConnectionType = %q, want unix", u.ConnectionType())
				}
			},
		},
		{
			name: "tls",
			input: `{
				"type": "tls",
				"caTrustType": "pinned",
				"serverCertFingerprint": "sha256:` + strings.Repeat("a", 64) + `",
				"serverCertSubject": "engine.example",
				"serverCertIssuer": "Example CA"
			}`,
			check: func(t *testing.T, c endpoint.Engine) {
				tc, ok := c.(endpoint.EngineTLS)
				if !ok {
					t.Fatalf("type = %T, want EngineTLS", c)
				}
				if tc.ConnectionType() != "tls" {
					t.Errorf("ConnectionType = %q, want tls", tc.ConnectionType())
				}
				if tc.CATrustType != "pinned" {
					t.Errorf("CATrustType = %q, want pinned", tc.CATrustType)
				}
				if tc.ServerCertSubject != "engine.example" {
					t.Errorf("ServerCertSubject = %q, want engine.example", tc.ServerCertSubject)
				}
				if tc.ServerCertIssuer != "Example CA" {
					t.Errorf("ServerCertIssuer = %q, want Example CA", tc.ServerCertIssuer)
				}
			},
		},
		{
			name: "mtls",
			input: `{
				"type": "mtls",
				"caTrustType": "system",
				"serverCertFingerprint": "sha256:bb",
				"clientCertFingerprint": "sha256:cc",
				"clientCertSubject": "controller.example"
			}`,
			check: func(t *testing.T, c endpoint.Engine) {
				m, ok := c.(endpoint.EngineMTLS)
				if !ok {
					t.Fatalf("type = %T, want EngineMTLS", c)
				}
				if m.ConnectionType() != "mtls" {
					t.Errorf("ConnectionType = %q, want mtls", m.ConnectionType())
				}
				if m.ClientCertFingerprint != "sha256:cc" {
					t.Errorf("ClientCertFingerprint = %q, want sha256:cc", m.ClientCertFingerprint)
				}
				if m.ClientCertSubject != "controller.example" {
					t.Errorf("ClientCertSubject = %q, want controller.example", m.ClientCertSubject)
				}
			},
		},
		{
			name:    "missing data",
			input:   ``,
			wantErr: "engine connection missing",
		},
		{
			name:    "null",
			input:   `null`,
			wantErr: "engine connection missing",
		},
		{
			name:    "invalid json",
			input:   `{`,
			wantErr: "engine connection:",
		},
		{
			name:    "missing type discriminator",
			input:   `{"caTrustType": "pinned"}`,
			wantErr: "missing type discriminator",
		},
		{
			name:    "unknown type",
			input:   `{"type": "plaintext"}`,
			wantErr: "unknown engine connection type",
		},
		{
			name:    "tls decode error",
			input:   `{"type": "tls", "serverCertFingerprint": 123}`,
			wantErr: "decode tls engine connection",
		},
		{
			name:    "mtls decode error",
			input:   `{"type": "mtls", "clientCertFingerprint": 123}`,
			wantErr: "decode mtls engine connection",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := endpoint.UnmarshalEngine([]byte(tc.input))
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
				t.Fatalf("UnmarshalEngine: %v", err)
			}
			tc.check(t, c)
		})
	}
}
