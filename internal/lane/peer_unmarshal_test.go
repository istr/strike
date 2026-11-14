package lane_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
)

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
				"trust": {"cert": "@anchor@"}
			},
			{
				"type": "ssh",
				"host": "git.example",
				"knownHosts": [{"keyType": "ssh-ed25519", "key": "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}]
			}
		]
	}`

	var s lane.Step
	if err := json.Unmarshal([]byte(withAnchor(input)), &s); err != nil {
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
	original := []byte(withAnchor(`{
		"name": "fetch",
		"image": "alpine:3.20",
		"args": [],
		"env": {},
		"inputs": [],
		"outputs": [],
		"secrets": [],
		"peers": [
			{"type": "https", "host": "registry.example.com", "trust": {"cert": "@anchor@"}}
		]
	}`))

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

// TestStep_OCIPeerRejected confirms the oci peer type was
// removed: a step declaring it fails to parse. See ADR-029.
func TestStep_OCIPeerRejected(t *testing.T) {
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

// TestRegistry_Decode exercises the decode of one registries entry: the
// registry and its storages decode to endpoint.TLS through the packed
// authority, an absent storages list decodes empty, and a malformed registry
// or storage is an error.
func TestRegistry_Decode(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantErr      string
		wantRegistry endpoint.Authority
		wantStorages []endpoint.Authority
	}{
		{
			name: "registry with storages",
			input: `{
				"registry": {"type": "https", "host": "images.example.com", "trust": {"cert": "@anchor@"}},
				"storages": [
					{"type": "https", "host": "blobs.example.com", "trust": {"cert": "@anchor@"}},
					{"type": "https", "host": "blobs.example.net:8443", "trust": {"mode": "leaf", "cert": "@anchor@"}}
				]
			}`,
			wantRegistry: "images.example.com",
			wantStorages: []endpoint.Authority{"blobs.example.com", "blobs.example.net:8443"},
		},
		{
			name:         "registry without storages",
			input:        `{"registry": {"type": "https", "host": "images.example.com", "trust": {"cert": "@anchor@"}}}`,
			wantRegistry: "images.example.com",
		},
		{
			name:    "registry missing trust",
			input:   `{"registry": {"type": "https", "host": "images.example.com"}}`,
			wantErr: "https endpoint: trust required",
		},
		{
			name:    "registry with empty host",
			input:   `{"registry": {"type": "https", "host": "", "trust": {"cert": "@anchor@"}}}`,
			wantErr: "empty host",
		},
		{
			name: "storage missing trust",
			input: `{
				"registry": {"type": "https", "host": "images.example.com", "trust": {"cert": "@anchor@"}},
				"storages": [{"type": "https", "host": "blobs.example.com"}]
			}`,
			wantErr: "https endpoint: trust required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r lane.Registry
			err := json.Unmarshal([]byte(withAnchor(tc.input)), &r)
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
				t.Fatalf("Registry decode: %v", err)
			}
			if got := r.Registry.Address.Authority(); got != tc.wantRegistry {
				t.Errorf("registry authority = %q, want %q", got, tc.wantRegistry)
			}
			if r.Registry.Trust.Cert == "" {
				t.Error("registry trust cert is empty")
			}
			if len(r.Storages) != len(tc.wantStorages) {
				t.Fatalf("storages len = %d, want %d", len(r.Storages), len(tc.wantStorages))
			}
			for i, want := range tc.wantStorages {
				if got := r.Storages[i].Address.Authority(); got != want {
					t.Errorf("storages[%d] authority = %q, want %q", i, got, want)
				}
			}
		})
	}
}
