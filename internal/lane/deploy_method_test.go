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
			name: "kubernetes",
			input: `{
				"method": {
					"type": "kubernetes",
					"image": "img@sha256:` + strings.Repeat("a", 64) + `",
					"namespace": "production",
					"strategy": "apply",
					"kubeconfig": "/etc/kubeconfig"
				},
				"artifacts": {},
				"target": {"type": "kubernetes", "description": "prod"},
				"attestation": {
					"pre_state": {"required": false, "capture": []},
					"post_state": {"required": false, "capture": []},
					"drift": {"detect": false, "on_drift": "warn"}
				}
			}`,
			check: func(t *testing.T, m lane.DeployMethod) {
				k, ok := m.(lane.DeployKubernetes)
				if !ok {
					t.Fatalf("Method type = %T, want DeployKubernetes", m)
				}
				if k.Namespace != "production" {
					t.Errorf("Namespace = %q, want production", k.Namespace)
				}
				if k.Strategy != "apply" {
					t.Errorf("Strategy = %q, want apply", k.Strategy)
				}
			},
		},
		{
			name: "registry",
			input: `{
				"method": {
					"type": "registry",
					"source": "src@sha256:` + strings.Repeat("b", 64) + `",
					"target": "dst.io/app:latest"
				},
				"artifacts": {},
				"target": {"type": "registry", "description": "prod"},
				"attestation": {
					"pre_state": {"required": false, "capture": []},
					"post_state": {"required": false, "capture": []},
					"drift": {"detect": false, "on_drift": "warn"}
				}
			}`,
			check: func(t *testing.T, m lane.DeployMethod) {
				r, ok := m.(lane.DeployRegistry)
				if !ok {
					t.Fatalf("Method type = %T, want DeployRegistry", m)
				}
				if r.Target != "dst.io/app:latest" {
					t.Errorf("Target = %q, want dst.io/app:latest", r.Target)
				}
			},
		},
		{
			name: "custom",
			input: `{
				"method": {
					"type": "custom",
					"image": "img@sha256:` + strings.Repeat("c", 64) + `",
					"args": ["deploy", "--prod"],
					"env": {"FOO": "bar"},
					"entrypoint": ["/bin/sh", "-c"]
				},
				"artifacts": {},
				"target": {"type": "custom", "description": "prod"},
				"attestation": {
					"pre_state": {"required": false, "capture": []},
					"post_state": {"required": false, "capture": []},
					"drift": {"detect": false, "on_drift": "warn"}
				}
			}`,
			check: func(t *testing.T, m lane.DeployMethod) {
				c, ok := m.(lane.DeployCustom)
				if !ok {
					t.Fatalf("Method type = %T, want DeployCustom", m)
				}
				if len(c.Args) != 2 {
					t.Errorf("Args len = %d, want 2", len(c.Args))
				}
				if c.Env["FOO"] != "bar" {
					t.Errorf("Env[FOO] = %q, want bar", c.Env["FOO"])
				}
			},
		},
		{
			name:    "unknown_type",
			input:   `{"method": {"type": "rsync"}}`,
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
			"source": "src@sha256:` + strings.Repeat("d", 64) + `",
			"target": "dst.io/app:latest"
		},
		"artifacts": {},
		"target": {"type": "registry", "description": "test"},
		"attestation": {
			"pre_state": {"required": false, "capture": []},
			"post_state": {"required": false, "capture": []},
			"drift": {"detect": false, "on_drift": "warn"}
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
