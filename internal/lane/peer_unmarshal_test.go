package lane_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
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
					"mode": "cert_fingerprint",
					"fingerprint": "sha256:` + strings.Repeat("a", 64) + `"
				}
			}`,
			check: func(t *testing.T, p lane.Peer) {
				h, ok := p.(lane.HTTPSPeer)
				if !ok {
					t.Fatalf("type = %T, want HTTPSPeer", p)
				}
				if h.Host != "example.com" {
					t.Errorf("Host = %q, want example.com", h.Host)
				}
				ft, ok := h.Trust.(transport.FingerprintTrust)
				if !ok {
					t.Fatalf("Trust type = %T, want FingerprintTrust", h.Trust)
				}
				if ft.Mode != "cert_fingerprint" {
					t.Errorf("Trust.Mode = %q, want cert_fingerprint", ft.Mode)
				}
			},
		},
		{
			name: "https with ca_bundle",
			input: `{
				"type": "https",
				"host": "internal.example",
				"trust": {
					"mode": "ca_bundle",
					"path": "/etc/ssl/ca.pem"
				}
			}`,
			check: func(t *testing.T, p lane.Peer) {
				h, ok := p.(lane.HTTPSPeer)
				if !ok {
					t.Fatalf("type = %T, want HTTPSPeer", p)
				}
				cb, ok := h.Trust.(transport.CABundleTrust)
				if !ok {
					t.Fatalf("Trust type = %T, want CABundleTrust", h.Trust)
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
				"known_hosts": [
					{"key_type": "ssh-ed25519", "key": "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}
				]
			}`,
			check: func(t *testing.T, p lane.Peer) {
				s, ok := p.(lane.SSHPeer)
				if !ok {
					t.Fatalf("type = %T, want SSHPeer", p)
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
			name: "https unknown trust mode",
			input: `{
				"type": "https",
				"host": "example.com",
				"trust": {"mode": "system_ca"}
			}`,
			wantErr: "unknown trust mode",
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
				"trust": {"mode": "cert_fingerprint", "fingerprint": "sha256:` + strings.Repeat("a", 64) + `"}
			},
			{
				"type": "ssh",
				"host": "git.example",
				"known_hosts": [{"key_type": "ssh-ed25519", "key": "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}]
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
	if _, ok := s.Peers[0].(lane.HTTPSPeer); !ok {
		t.Errorf("Peers[0] type = %T, want HTTPSPeer", s.Peers[0])
	}
	if _, ok := s.Peers[1].(lane.SSHPeer); !ok {
		t.Errorf("Peers[1] type = %T, want SSHPeer", s.Peers[1])
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
			{"type": "https", "host": "registry.example.com", "trust": {"mode": "cert_fingerprint", "fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
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
	if _, ok := s2.Peers[0].(lane.HTTPSPeer); !ok {
		t.Errorf("round-tripped Peers[0] type = %T, want HTTPSPeer", s2.Peers[0])
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
