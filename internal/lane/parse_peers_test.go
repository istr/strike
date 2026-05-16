package lane_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// TestParse_PeersAccept exercises every valid_*.yaml fixture under
// testdata/peers/. The fixture list is defined by glob, so adding a
// new valid_<feature>.yaml automatically extends coverage.
func TestParse_PeersAccept(t *testing.T) {
	matches, err := filepath.Glob("testdata/peers/valid_*.yaml")
	if err != nil {
		t.Fatalf("glob valid fixtures: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no valid_*.yaml fixtures found under testdata/peers/")
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			fp, fpErr := lane.NewFilePath(path)
			if fpErr != nil {
				t.Fatalf("NewFilePath(%s): %v", path, fpErr)
			}
			if _, err := lane.Parse(fp); err != nil {
				t.Errorf("Parse(%s): unexpected error: %v", path, err)
			}
		})
	}
}

// TestParse_PeersReject exercises every invalid_*.yaml fixture and
// asserts that the parse error contains a feature-specific substring.
// Each entry pairs a fixture filename with one substring; the
// substring is intentionally short and tied to the constraint that
// must be violated, not to a particular CUE error rendering.
func TestParse_PeersReject(t *testing.T) {
	tests := []struct {
		fixture      string
		wantContains string
	}{
		{"invalid_https_empty_host.yaml", "host"},
		{"invalid_https_no_trust.yaml", "trust"},
		{"invalid_https_unknown_trust_mode.yaml", "trust"},
		{"invalid_https_uppercase_host.yaml", "host"},
		{"invalid_https_underscore_host.yaml", "host"},
		{"invalid_https_short_fingerprint.yaml", "fingerprint"},
		{"invalid_https_no_sha_prefix.yaml", "fingerprint"},
		{"invalid_https_ca_bundle_relative_path.yaml", "path"},
		{"invalid_https_ca_bundle_dotdot.yaml", "path"},
		{"invalid_ssh_invalid_key_type.yaml", "type"},
		{"invalid_ssh_key_with_pem_armor.yaml", "key"},
		{"invalid_ssh_hashed_known_hosts.yaml", "key"},
		{"invalid_oci_uppercase_registry.yaml", "registry"},
		{"invalid_peer_unknown_type.yaml", "type"},
	}

	// Sanity: every invalid_*.yaml on disk must be in the table.
	matches, err := filepath.Glob("testdata/peers/invalid_*.yaml")
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
			path := filepath.Join("testdata", "peers", tc.fixture)
			fp, fpErr := lane.NewFilePath(path)
			if fpErr != nil {
				t.Fatalf("NewFilePath(%s): %v", path, fpErr)
			}
			_, err := lane.Parse(fp)
			if err == nil {
				t.Fatalf("Parse(%s): expected error, got nil", path)
			}
			if !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("Parse(%s): error %q does not contain %q",
					path, err.Error(), tc.wantContains)
			}
		})
	}
}
