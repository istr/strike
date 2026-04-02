package deploy_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

func TestValidateAttestation_Valid(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Target:    lane.DeployTarget{Type: "registry", Description: "production"},
		Artifacts: map[string]string{
			"image": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		PreState: map[string]deploy.StateSnap{
			"version": {
				Name:      "version",
				Image:     "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Timestamp: time.Date(2025, 1, 15, 10, 30, 1, 0, time.UTC),
			},
		},
		PostState: map[string]deploy.StateSnap{
			"version": {
				Name:      "version",
				Image:     "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
				Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Timestamp: time.Date(2025, 1, 15, 10, 31, 0, 0, time.UTC),
			},
		},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
}

func TestValidateAttestation_WithEngine(t *testing.T) {
	rootless := true
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Target:    lane.DeployTarget{Type: "kubernetes", Description: "staging"},
		Artifacts: map[string]string{
			"app": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
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
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with engine record rejected: %v", err)
	}
}

func TestValidateAttestation_WithDrift(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "abcdef0123456789",
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Target:    lane.DeployTarget{Type: "registry", Description: "production"},
		Artifacts: map[string]string{},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
		Drift: &deploy.DriftReport{
			PreviousDeployID:  "9876543210fedcba",
			PreviousPostState: map[string]string{"version": "sha256:aaa"},
			CurrentPreState:   map[string]string{"version": "sha256:bbb"},
			Drifted:           []string{"version"},
		},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with drift rejected: %v", err)
	}
}

func TestValidateAttestation_InvalidDeployID(t *testing.T) {
	att := &deploy.Attestation{
		DeployID:  "NOT-HEX!!", // too short, wrong chars
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Target:    lane.DeployTarget{Type: "registry", Description: "test"},
		Artifacts: map[string]string{},
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
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Target:    lane.DeployTarget{Type: "registry", Description: "test"},
		Artifacts: map[string]string{},
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
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Target:    lane.DeployTarget{Type: "registry", Description: "first deploy"},
		Artifacts: map[string]string{},
		PreState:  map[string]deploy.StateSnap{},
		PostState: map[string]deploy.StateSnap{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("empty states should be valid: %v", err)
	}
}
