package deploy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

func TestValidateAttestation_Valid(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{Type: "registry", Description: "production"},
		Artifacts: map[string]deploy.SignedArtifact{
			"image": {Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		PreState: map[string]deploy.StateSnap{
			"version": {
				Name:      "version",
				Image:     "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Timestamp: clock.Unix(1, 0),
			},
		},
		PostState: map[string]deploy.StateSnap{
			"version": {
				Name:      "version",
				Image:     "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Timestamp: clock.Unix(60, 0),
			},
		},
		Peers: map[string][]lane.Peer{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
}

func TestValidateAttestation_WithEngine(t *testing.T) {
	rootless := true
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{Type: "kubernetes", Description: "staging"},
		Artifacts: map[string]deploy.SignedArtifact{
			"app": {Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
		Engine: &deploy.EngineRecord{
			ConnectionType:        "tls",
			CATrustMode:           "pinned",
			ServerCertFingerprint: "sha256:cccccccccccccccccccccc",
			Rootless:              &rootless,
			Version:               "5.3.1",
		},
		Peers: map[string][]lane.Peer{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with engine record rejected: %v", err)
	}
}

func TestValidateAttestation_WithDrift(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{Type: "registry", Description: "production"},
		Artifacts: map[string]deploy.SignedArtifact{},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
		Drift: &deploy.DriftReport{
			PreviousDeployID:  "9876543210fedcba",
			PreviousPostState: map[string]string{"version": "sha256:aaa"},
			CurrentPreState:   map[string]string{"version": "sha256:bbb"},
			Drifted:           []string{"version"},
		},
		Peers: map[string][]lane.Peer{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with drift rejected: %v", err)
	}
}

func TestValidateAttestation_InvalidDeployID(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "NOT-HEX!!", // too short, wrong chars
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{Type: "registry", Description: "test"},
		Artifacts: map[string]deploy.SignedArtifact{},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
	}

	if err := deploy.ValidateAttestation(att); err == nil {
		t.Fatal("expected validation error for invalid deploy_id")
	}
}

func TestValidateAttestation_InvalidEngineConnectionType(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{Type: "registry", Description: "test"},
		Artifacts: map[string]deploy.SignedArtifact{},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
		Engine: &deploy.EngineRecord{
			ConnectionType: "plaintext", // not in enum
		},
	}

	if err := deploy.ValidateAttestation(att); err == nil {
		t.Fatal("expected validation error for invalid connection_type")
	}
}

func TestValidateAttestation_MissingTarget(t *testing.T) {
	// Build a minimal attestation with missing target fields via raw JSON
	// to bypass Go struct defaults.
	raw := `{
		"deploy_id": "abcdef0123456789",
		"timestamp": "2025-01-15T10:30:00Z",
		"artifacts": {},
		"pre_state": {},
		"post_state": {}
	}`

	var att deploy.Attestation
	if err := json.Unmarshal([]byte(raw), &att); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := deploy.ValidateAttestation(&att); err == nil {
		t.Fatal("expected validation error for missing target")
	}
}

func TestValidateAttestation_EmptyStatesAllowed(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{Type: "registry", Description: "first deploy"},
		Artifacts: map[string]deploy.SignedArtifact{},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
		Peers:     map[string][]lane.Peer{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("empty states should be valid: %v", err)
	}
}

// crossvalDir is the path to cross-validation test vectors.
const crossvalDir = "../../test/crossval"

// attestationVector is the Go representation of a ValidateAttestation test vector.
type attestationInputs struct {
	Attestation json.RawMessage `json:"attestation"`
}

type attestationExpected struct {
	ErrorContains string `json:"error_contains"`
	Valid         bool   `json:"valid"`
}

type attestationVector struct {
	Boundary    string              `json:"boundary"`
	Description string              `json:"description"`
	Inputs      attestationInputs   `json:"inputs"`
	Expected    attestationExpected `json:"expected"`
}

func TestValidateAttestation_Crossval(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(crossvalDir, "attestation", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no attestation vectors found")
	}

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			runAttestationVector(t, f)
		})
	}
}

func runAttestationVector(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a hardcoded test constant, not user input
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vec attestationVector
	if err := json.Unmarshal(data, &vec); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}

	valErr := deploy.ValidateAttestationJSON(vec.Inputs.Attestation)

	if vec.Expected.Valid {
		if valErr != nil {
			t.Fatalf("expected valid, got error: %v", valErr)
		}
		return
	}
	if valErr == nil {
		t.Fatal("expected validation error, got nil")
	}
	if vec.Expected.ErrorContains != "" && !strings.Contains(valErr.Error(), vec.Expected.ErrorContains) {
		t.Errorf("error %q does not contain %q", valErr.Error(), vec.Expected.ErrorContains)
	}
}
