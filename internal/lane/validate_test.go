package lane_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// parseAndValidate runs the full lane-structure gate -- Parse then
// ValidateLane -- and returns the first error, mirroring the CLI
// orchestration up to the point a lane is structurally rejected. Topology
// validation (Build, ValidateLeavesAreDeploys) is not part of this helper.
func parseAndValidate(t *testing.T, path string) error {
	t.Helper()
	fp, err := lane.NewFilePath(path)
	if err != nil {
		t.Fatalf("NewFilePath(%s): %v", path, err)
	}
	p, index, _, err := lane.Parse(fp)
	if err != nil {
		return err
	}
	return lane.ValidateLane(p, index)
}

// TestValidateLane_Reject exercises every invalid_*.yaml under
// testdata/validate/ through the full validation gate and asserts the
// intended error surfaces. The fixture list is glob-checked against the
// table, so adding a fixture without a table entry fails the test.
func TestValidateLane_Reject(t *testing.T) {
	tests := []struct {
		fixture      string
		wantContains string
	}{
		{"invalid_unknown_input_step.yaml", "unknown step"},
		{"invalid_input_output_not_found.yaml", "not found"},
		{"invalid_image_from_no_image_output.yaml", "declares no image output"},
		{"invalid_duplicate_output_id.yaml", "duplicate output id"},
		{"invalid_subpath_on_file_output.yaml", "subpath"},
		{"invalid_mount_overlap.yaml", "overlap"},
		{"invalid_provenance_path_outside_output.yaml", "not within any declared output"},
	}

	matches, err := filepath.Glob("testdata/validate/invalid_*.yaml")
	if err != nil {
		t.Fatalf("glob invalid fixtures: %v", err)
	}
	have := map[string]bool{}
	for _, m := range matches {
		have[filepath.Base(m)] = true
	}
	for _, tc := range tests {
		delete(have, tc.fixture)
	}
	if len(have) > 0 {
		t.Errorf("invalid fixtures on disk not covered by table: %v", have)
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			path := filepath.Join("testdata", "validate", tc.fixture)
			err := parseAndValidate(t, path)
			if err == nil {
				t.Fatalf("validate(%s): expected error, got nil", path)
			}
			if !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("validate(%s): error %q does not contain %q",
					path, err.Error(), tc.wantContains)
			}
		})
	}
}
