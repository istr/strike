package deploy_test

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
	"github.com/istr/strike/test/crossval"
)

func TestValidateAttestation_Valid(t *testing.T) {
	att := &deploy.Attestation{
		LaneID:    "test-lane",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
		Artifacts: map[string]deploy.SignedArtifact{
			"image": {Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		PreStateDigest:  lane.MustParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		PostStateDigest: lane.MustParseDigest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Peers:           map[string][]lane.Peer{},
		Provenance:      []lane.ProvenanceRecord{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
}

func TestValidateAttestation_WithEngine(t *testing.T) {
	rootless := true
	att := &deploy.Attestation{
		LaneID:    "test-lane",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{ID: "staging-1", Type: "kubernetes", Description: "staging"},
		Artifacts: map[string]deploy.SignedArtifact{
			"app": {Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		},
		PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Engine: &deploy.EngineRecord{
			ConnectionType:        "tls",
			CATrustMode:           "pinned",
			ServerCertFingerprint: "sha256:cccccccccccccccccccccc",
			Rootless:              &rootless,
			Version:               "5.3.1",
		},
		Peers:      map[string][]lane.Peer{},
		Provenance: []lane.ProvenanceRecord{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with engine record rejected: %v", err)
	}
}

func TestValidateAttestation_InvalidEngineConnectionType(t *testing.T) {
	att := &deploy.Attestation{
		LaneID:          "test-lane",
		Timestamp:       clock.Reproducible(),
		Target:          lane.DeployTarget{ID: "test-1", Type: "registry", Description: "test"},
		Artifacts:       map[string]deploy.SignedArtifact{},
		PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Engine: &deploy.EngineRecord{
			ConnectionType: "plaintext", // not in enum
		},
		Peers:      map[string][]lane.Peer{},
		Provenance: []lane.ProvenanceRecord{},
	}

	if err := deploy.ValidateAttestation(att); err == nil {
		t.Fatal("expected validation error for invalid connection_type")
	}
}

func TestValidateAttestation_MissingTarget(t *testing.T) {
	raw := `{
		"lane_id": "test-lane",
		"timestamp": "2025-01-15T10:30:00Z",
		"artifacts": {},
		"pre_state_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"post_state_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`

	var att deploy.Attestation
	if err := json.Unmarshal([]byte(raw), &att); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := deploy.ValidateAttestation(&att); err == nil {
		t.Fatal("expected validation error for missing target")
	}
}

func TestValidateAttestation_EmptyDigestsAllowed(t *testing.T) {
	att := &deploy.Attestation{
		LaneID:          "test-lane",
		Timestamp:       clock.Reproducible(),
		Target:          lane.DeployTarget{ID: "test-1", Type: "registry", Description: "first deploy"},
		Artifacts:       map[string]deploy.SignedArtifact{},
		PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Peers:           map[string][]lane.Peer{},
		Provenance:      []lane.ProvenanceRecord{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("empty captures should be valid: %v", err)
	}
}

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
	files, err := fs.Glob(crossval.FS, "attestation/*.json")
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

func runAttestationVector(t *testing.T, name string) {
	t.Helper()

	data, err := crossval.FS.ReadFile(name)
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

func TestValidateAttestation_WithResolverRecord(t *testing.T) {
	att := &deploy.Attestation{
		LaneID:          "test-lane",
		Timestamp:       clock.Reproducible(),
		Target:          lane.DeployTarget{ID: "staging-1", Type: "kubernetes", Description: "staging"},
		Artifacts:       map[string]deploy.SignedArtifact{},
		PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Resolver: &deploy.ResolverRecord{
			Host:                  "1.1.1.1:853",
			ServerCertFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			TLSVersion:            "TLS 1.3",
			CipherSuite:           "TLS_AES_128_GCM_SHA256",
		},
		Peers:      map[string][]lane.Peer{},
		Provenance: []lane.ProvenanceRecord{},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with resolver record rejected: %v", err)
	}
}

func TestValidateAttestation_WithPeers(t *testing.T) {
	att := &deploy.Attestation{
		LaneID:    "test-lane",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
		Artifacts: map[string]deploy.SignedArtifact{
			"image": {Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Provenance:      []lane.ProvenanceRecord{},
		Peers: map[string][]lane.Peer{
			"build": {
				lane.HTTPSPeer{
					Type: "https",
					Host: transport.Host("api.example.com"),
					Trust: transport.FingerprintTrust{
						Mode:        "cert_fingerprint",
						Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
					},
				},
			},
			"clone": {
				lane.SSHPeer{
					Type: "ssh",
					Host: transport.Host("git.example.com"),
					KnownHosts: []lane.KnownHostEntry{
						{
							KeyType: "ssh-ed25519",
							Key:     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
						},
					},
				},
			},
		},
	}

	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation with valid peers rejected: %v", err)
	}
}

func TestValidateAttestation_InvalidPeer(t *testing.T) {
	att := &deploy.Attestation{
		LaneID:    "test-lane",
		Timestamp: clock.Reproducible(),
		Target:    lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
		Artifacts: map[string]deploy.SignedArtifact{
			"image": {Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
		PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Provenance:      []lane.ProvenanceRecord{},
		Peers: map[string][]lane.Peer{
			"build": {
				lane.HTTPSPeer{
					Type: "https",
					Host: transport.Host("api.example.com"),
					// Trust deliberately nil -- triggers schema reject.
				},
			},
		},
	}

	err := deploy.ValidateAttestation(att)
	if err == nil {
		t.Fatal("attestation with HTTPS peer missing trust was accepted")
	}
	if !strings.Contains(err.Error(), "trust") {
		t.Errorf("error %q does not mention 'trust'", err.Error())
	}
}
