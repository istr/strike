package lane_test

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/istr/strike/internal/lane"
)

//go:embed testdata/valid_trustroot_inline.yaml testdata/peers/valid_ssh_known_hosts.yaml testdata/peers/valid_state_capture_peers.yaml
var nonEmptyListBases embed.FS

// TestParse_RejectsAbsentNonEmptyLists derives each case from a valid fixture:
// it removes one list the contract declares non-empty, or empties it, and
// requires schema validation to reject the lane and name the field (ADR-049
// rule 6).
func TestParse_RejectsAbsentNonEmptyLists(t *testing.T) {
	const trustRoot = "testdata/valid_trustroot_inline.yaml"
	tests := []struct {
		fixture string
		field   string
		parents []any
	}{
		{"testdata/peers/valid_state_capture_peers.yaml", "command", []any{"steps", 1, "deploy", "recording", "preState", "captures", 0}},
		{"testdata/peers/valid_ssh_known_hosts.yaml", "knownHosts", []any{"steps", 0, "peers", 0}},
		{trustRoot, "tlogs", []any{"keyless", "trustRoot"}},
		{trustRoot, "ctlogs", []any{"keyless", "trustRoot"}},
		{trustRoot, "certificateAuthorities", []any{"keyless", "trustRoot"}},
		{trustRoot, "timestampAuthorities", []any{"keyless", "trustRoot"}},
		{trustRoot, "certificates", []any{"keyless", "trustRoot", "certificateAuthorities", 0, "certChain"}},
	}
	for _, tc := range tests {
		for _, empty := range []bool{false, true} {
			name := tc.field + "/absent"
			if empty {
				name = tc.field + "/empty"
			}
			t.Run(name, func(t *testing.T) {
				path := writeListVariant(t, tc.fixture, tc.parents, tc.field, empty)
				_, _, _, err := lane.Parse(mustFilePath(t, path))
				if err == nil {
					t.Fatal("Parse accepted the lane")
				}
				if msg := err.Error(); !strings.Contains(msg, "validation:") || !strings.Contains(msg, tc.field) {
					t.Fatalf("Parse error is not a schema rejection naming %s: %v", tc.field, err)
				}
			})
		}
	}
}

// writeListVariant loads fixture, walks parents to the map that holds field,
// removes field from it (or sets it to an empty list when empty is true), and
// writes the document as JSON, which the lane parser reads as YAML, to a
// temporary file whose path it returns.
func writeListVariant(t *testing.T, fixture string, parents []any, field string, empty bool) string {
	t.Helper()
	raw, readErr := nonEmptyListBases.ReadFile(fixture)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var doc any
	if yamlErr := yaml.Unmarshal(raw, &doc); yamlErr != nil {
		t.Fatal(yamlErr)
	}
	node := doc
	for _, key := range parents {
		switch k := key.(type) {
		case string:
			m, ok := node.(map[string]any)
			if !ok {
				t.Fatalf("%s: %q is not a map key here", fixture, k)
			}
			node = m[k]
		case int:
			s, ok := node.([]any)
			if !ok || k >= len(s) {
				t.Fatalf("%s: %d is not a list index here", fixture, k)
			}
			node = s[k]
		default:
			t.Fatalf("%s: path element %v is neither a key nor an index", fixture, key)
		}
	}
	holder, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%s: %v does not lead to a map", fixture, parents)
	}
	if _, present := holder[field]; !present {
		t.Fatalf("%s: the valid fixture has no %s to remove", fixture, field)
	}
	if empty {
		holder[field] = []any{}
	} else {
		delete(holder, field)
	}
	data, jsonErr := json.Marshal(doc)
	if jsonErr != nil {
		t.Fatal(jsonErr)
	}
	path := filepath.Join(t.TempDir(), "lane.yaml")
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	return path
}
