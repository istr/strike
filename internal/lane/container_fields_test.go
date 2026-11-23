package lane_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/istr/strike/internal/testutil"
)

const (
	packReason   = "a pack step starts no container; only a step container reads this field"
	deployReason = "a deploy step starts no container; only a step container reads this field"
)

// containerFieldCase sets one field of one step of the valid force-run
// fixture to value. want is the schema rejection the lane must produce, or
// empty when the lane is accepted.
type containerFieldCase struct {
	value any
	name  string
	field string
	want  string
	step  int
}

// containerFieldCases builds the cases for the pack step (steps.1) and the
// deploy step (steps.2) of the valid force-run fixture: a value of each list
// and map field a step container reads, a workdir, a timeout, and forceRun on
// both kinds.
func containerFieldCases() []containerFieldCase {
	nonEmpty := map[string]any{
		"args":    []any{"x"},
		"inputs":  []any{map[string]any{"from": map[string]any{"step": "clone", "output": "repo"}, "mount": "/in"}},
		"outputs": []any{map[string]any{"id": "f", "type": "file", "path": "f"}},
		"secrets": []any{map[string]any{"name": "step-secret", "env": "T"}},
		"peers":   []any{map[string]any{"type": "https", "host": "example.com", "trust": map[string]any{"cert": testutil.AnchorCertB64}}},
	}
	var cases []containerFieldCase
	for _, kind := range []struct {
		name   string
		reason string
		step   int
	}{{"pack", packReason, 1}, {"deploy", deployReason, 2}} {
		at := fmt.Sprintf("#Lane.steps.%d.", kind.step)
		for _, field := range []string{"args", "inputs", "outputs", "secrets", "peers"} {
			cases = append(cases,
				containerFieldCase{nonEmpty[field], kind.name + " " + field, field, at + field + ": " + kind.reason, kind.step})
		}
		cases = append(cases,
			containerFieldCase{map[string]any{"K": "v"}, kind.name + " env", "env", at + "env: " + kind.reason, kind.step},
			containerFieldCase{"/w", kind.name + " workdir", "workdir", at + "workdir: " + kind.reason, kind.step},
			containerFieldCase{"5m", kind.name + " timeout", "timeout", "", kind.step})
	}
	return append(cases,
		containerFieldCase{true, "pack forceRun", "forceRun", "", 1},
		containerFieldCase{true, "deploy forceRun", "forceRun", "#Lane.steps.2.forceRun: " + deployReason, 2},
		containerFieldCase{false, "deploy forceRun false", "forceRun", "", 2})
}

// TestParse_ContainerFieldsOnDeployAndPack derives each case from the valid
// force-run fixture, whose steps are a container step, a pack step and a
// deploy step, by setting one field of the pack or the deploy step. A deploy
// step and a pack step start no container (ADR-051 D1): a field only a step
// container reads is rejected by the schema at the field, with the reason,
// whatever its value, while a timeout, a pack step's forceRun and a deploy
// step's forceRun false are accepted.
func TestParse_ContainerFieldsOnDeployAndPack(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid_force_run_minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range containerFieldCases() {
		t.Run(tc.name, func(t *testing.T) {
			err := parseAndValidate(t, writeStepVariant(t, raw, tc.step, tc.field, tc.value))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("lane rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "validation:") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a schema rejection containing %q", err, tc.want)
			}
		})
	}
}

// writeStepVariant loads the fixture raw, declares the lane secret
// step-secret, sets field of steps[step] to value, and writes the document as
// JSON, which the lane parser reads as YAML, to a temporary file whose path
// it returns.
func writeStepVariant(t *testing.T, raw []byte, step int, field string, value any) string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	secrets, ok := doc["secrets"].(map[string]any)
	if !ok {
		t.Fatal("fixture declares no lane secrets map")
	}
	secrets["step-secret"] = "env://STEP_SECRET"
	steps, ok := doc["steps"].([]any)
	if !ok || step >= len(steps) {
		t.Fatalf("fixture has no step %d", step)
	}
	st, ok := steps[step].(map[string]any)
	if !ok {
		t.Fatalf("fixture step %d is not a map", step)
	}
	st[field] = value
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lane.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
