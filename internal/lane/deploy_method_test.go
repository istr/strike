package lane_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// Each subtest unmarshals a DeploySpec JSON snippet and asserts
// that Method is the expected concrete branch type with the
// expected field values.
func TestDeploySpec_UnmarshalJSON_Discriminator(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		check   func(t *testing.T, m lane.DeployMethod)
		wantErr string
	}{
		{
			// The kubernetes method is suspended (ADR-054) but keeps its
			// discriminator, its disjunction arm and this dispatch, so a lane
			// declaring it still parses and is rejected at validation instead.
			name: "kubernetes",
			input: `{
				"method": {"type": "kubernetes"},
				"artifacts": {},
				"attestation": {
					"preState": {"required": false, "capture": []},
					"postState": {"required": false, "capture": []}
				}
			}`,
			check: func(t *testing.T, m lane.DeployMethod) {
				k, ok := m.(lane.DeployKubernetes)
				if !ok {
					t.Fatalf("Method type = %T, want DeployKubernetes", m)
				}
				if k.MethodType() != "kubernetes" {
					t.Errorf("MethodType = %q, want kubernetes", k.MethodType())
				}
			},
		},
		{
			name: "registry",
			input: `{
				"method": {
					"type": "registry",
					"target": {
						"host": "dst.io",
						"trust": {"type": "certFingerprint", "fingerprint": "sha256:` + strings.Repeat("b", 64) + `"},
						"name": "app"
					}
				},
				"artifacts": {},
				"target": {"type": "registry", "description": "prod"},
				"attestation": {
					"preState": {"required": false, "capture": []},
					"postState": {"required": false, "capture": []}
				}
			}`,
			check: func(t *testing.T, m lane.DeployMethod) {
				r, ok := m.(lane.DeployRegistry)
				if !ok {
					t.Fatalf("Method type = %T, want DeployRegistry", m)
				}
				if string(r.Target.Address.Authority()) != "dst.io" {
					t.Errorf("Target.Address = %q, want dst.io", r.Target.Address.Authority())
				}
				if r.Target.Name != "app" {
					t.Errorf("Target.Name = %q, want app", r.Target.Name)
				}
			},
		},
		{
			name:    "unknown_type",
			input:   `{"method": {"type": "rsync"}}`,
			wantErr: "unknown deploy method type",
		},
		{
			name:    "custom_removed",
			input:   `{"method": {"type": "custom"}}`,
			wantErr: "unknown deploy method type",
		},
		{
			name:    "missing_type",
			input:   `{"method": {"image": "irrelevant"}}`,
			wantErr: "missing type discriminator",
		},
		{
			name:    "missing_method",
			input:   `{}`,
			wantErr: "deploy method missing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var spec lane.DeploySpec
			err := json.Unmarshal([]byte(tc.input), &spec)
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
				t.Fatalf("unmarshal: %v", err)
			}
			tc.check(t, spec.Method)
		})
	}
}

// Round-trip test: marshalling the unmarshalled spec must produce
// JSON whose method.type matches the original.
func TestDeploySpec_RoundTrip(t *testing.T) {
	original := `{
		"method": {
			"type": "registry",
			"target": {
				"host": "dst.io",
				"trust": {"type": "certFingerprint", "fingerprint": "sha256:` + strings.Repeat("d", 64) + `"},
				"name": "app"
			}
		},
		"artifacts": {},
		"target": {"type": "registry", "description": "test"},
		"attestation": {
			"preState": {"required": false, "capture": []},
			"postState": {"required": false, "capture": []}
		}
	}`

	var spec lane.DeploySpec
	if err := json.Unmarshal([]byte(original), &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	out, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var roundtrip map[string]any
	if err := json.Unmarshal(out, &roundtrip); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}

	method, ok := roundtrip["method"].(map[string]any)
	if !ok {
		t.Fatal("method key missing or not an object after marshal")
	}
	if method["type"] != "registry" {
		t.Errorf("round-tripped method.type = %v, want registry", method["type"])
	}
}
