package lane_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
)

func TestUnmarshalPeer_Discriminator(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		check   func(t *testing.T, p lane.Peer)
		wantErr string
	}{
		{
			name: "https with fingerprint",
			input: `{
				"type": "https",
				"host": "example.com",
				"trust": {
					"type": "certFingerprint",
					"fingerprint": "sha256:` + strings.Repeat("a", 64) + `"
				}
			}`,
			check: func(t *testing.T, p lane.Peer) {
				h, ok := p.(endpoint.TLS)
				if !ok {
					t.Fatalf("type = %T, want endpoint.TLS", p)
				}
				if h.Address.Authority() != "example.com" {
					t.Errorf("Host = %q, want example.com", h.Address.Authority())
				}
				ft, ok := h.Trust.(endpoint.Fingerprint)
				if !ok {
					t.Fatalf("Trust type = %T, want endpoint.Fingerprint", h.Trust)
				}
				if ft.Type != "certFingerprint" {
					t.Errorf("Trust.Type = %q, want certFingerprint", ft.Type)
				}
			},
		},
		{
			name: "https with caBundle",
			input: `{
				"type": "https",
				"host": "internal.example",
				"trust": {
					"type": "caBundle",
					"path": "/etc/ssl/ca.pem"
				}
			}`,
			check: func(t *testing.T, p lane.Peer) {
				h, ok := p.(endpoint.TLS)
				if !ok {
					t.Fatalf("type = %T, want endpoint.TLS", p)
				}
				cb, ok := h.Trust.(endpoint.CABundle)
				if !ok {
					t.Fatalf("Trust type = %T, want endpoint.CABundle", h.Trust)
				}
				if cb.Path != "/etc/ssl/ca.pem" {
					t.Errorf("Trust.Path = %q, want /etc/ssl/ca.pem", cb.Path)
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
			check: func(t *testing.T, p lane.Peer) {
				s, ok := p.(endpoint.SSH)
				if !ok {
					t.Fatalf("type = %T, want endpoint.SSH", p)
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
			wantErr: "unknown peer type",
		},
		{
			name:    "unknown type",
			input:   `{"type": "ftp", "host": "example.com"}`,
			wantErr: "unknown peer type",
		},
		{
			name:    "missing type",
			input:   `{"host": "example.com"}`,
			wantErr: "missing type discriminator",
		},
		{
			name:    "https missing trust",
			input:   `{"type": "https", "host": "example.com"}`,
			wantErr: "trust required",
		},
		{
			name: "https unknown trust type",
			input: `{
				"type": "https",
				"host": "example.com",
				"trust": {"type": "system_ca"}
			}`,
			wantErr: "unknown trust type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := lane.UnmarshalPeer([]byte(tc.input))
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
				t.Fatalf("UnmarshalPeer: %v", err)
			}
			tc.check(t, p)
		})
	}
}

// TestStep_UnmarshalJSON_Peers exercises the slice-level
// dispatch on the Step type, ensuring that all branches in a
// multi-peer step decode to their concrete types.
func TestStep_UnmarshalJSON_Peers(t *testing.T) {
	input := `{
		"name": "fetch",
		"image": "alpine:3.20",
		"args": ["/bin/true"],
		"env": {},
		"inputs": [],
		"outputs": [],
		"secrets": [],
		"peers": [
			{
				"type": "https",
				"host": "example.com",
				"trust": {"type": "certFingerprint", "fingerprint": "sha256:` + strings.Repeat("a", 64) + `"}
			},
			{
				"type": "ssh",
				"host": "git.example",
				"knownHosts": [{"keyType": "ssh-ed25519", "key": "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}]
			}
		]
	}`

	var s lane.Step
	if err := json.Unmarshal([]byte(input), &s); err != nil {
		t.Fatalf("Step UnmarshalJSON: %v", err)
	}
	if len(s.Peers) != 2 {
		t.Fatalf("Peers len = %d, want 2", len(s.Peers))
	}
	if _, ok := s.Peers[0].(endpoint.TLS); !ok {
		t.Errorf("Peers[0] type = %T, want endpoint.TLS", s.Peers[0])
	}
	if _, ok := s.Peers[1].(endpoint.SSH); !ok {
		t.Errorf("Peers[1] type = %T, want endpoint.SSH", s.Peers[1])
	}
}

// TestStep_RoundTrip ensures that unmarshalling a Step with
// peers and re-marshalling it produces JSON that re-unmarshals
// to the same shape.
func TestStep_RoundTrip(t *testing.T) {
	original := []byte(`{
		"name": "fetch",
		"image": "alpine:3.20",
		"args": [],
		"env": {},
		"inputs": [],
		"outputs": [],
		"secrets": [],
		"peers": [
			{"type": "https", "host": "registry.example.com", "trust": {"type": "certFingerprint", "fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
		]
	}`)

	var s lane.Step
	if err := json.Unmarshal(original, &s); err != nil {
		t.Fatalf("unmarshal 1: %v", err)
	}

	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var s2 lane.Step
	if err := json.Unmarshal(out, &s2); err != nil {
		t.Fatalf("unmarshal 2: %v", err)
	}
	if len(s2.Peers) != 1 {
		t.Fatalf("round-tripped Peers len = %d, want 1", len(s2.Peers))
	}
	if _, ok := s2.Peers[0].(endpoint.TLS); !ok {
		t.Errorf("round-tripped Peers[0] type = %T, want endpoint.TLS", s2.Peers[0])
	}
}

// TestUnmarshalPeer_OCIRejected confirms the oci peer type was
// removed: a step declaring it fails to parse. See ADR-029.
func TestUnmarshalPeer_OCIRejected(t *testing.T) {
	raw := []byte(`{
		"name": "fetch",
		"image": "alpine:3.20",
		"args": [],
		"env": {},
		"inputs": [],
		"outputs": [],
		"secrets": [],
		"peers": [
			{"type": "oci", "registry": "docker.io"}
		]
	}`)
	var s lane.Step
	err := json.Unmarshal(raw, &s)
	if err == nil {
		t.Fatal("expected error for oci peer type, got nil")
	}
	if !strings.Contains(err.Error(), "oci") {
		t.Errorf("error %q does not mention the rejected type", err)
	}
}
