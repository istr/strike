package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

func TestDeployAttestation(t *testing.T) {
	engine := needsEngine(t)
	ctx := context.Background()
	keyPEM := generateTestKey(t)

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// Build, pack, and load into local store.
	binPath := buildTestBinary(t, engine)
	_, packRoot, _ := packTestImage(t, binPath, keyPEM)
	defer packRoot.Close() //nolint:errcheck // os.Root.Close on temp dir; error is not actionable in test

	regClient := &registry.Client{Engine: engine}
	packedDigest, err := regClient.LoadOCITar(ctx, packRoot, "image.tar")
	if err != nil {
		t.Fatalf("load OCI tar: %v", err)
	}
	t.Logf("packed image: %s", packedDigest)

	// Local tag assigned by LoadOCITar for podman lookups.
	localTag := "localhost/strike:" + strings.TrimPrefix(packedDigest, "sha256:")[:12]

	// Register the packed artifact in lane state.
	state := lane.NewState()
	if regErr := state.Register("pack", "image", lane.Artifact{
		Type:   "image",
		Digest: packedDigest,
	}); regErr != nil {
		t.Fatalf("register artifact: %v", regErr)
	}

	// Deploy using the "custom" method with the packed image.
	att := executeDeploy(t, engine, keyPEM, state, packedDigest, localTag)

	// Verify DSSE signature round-trip.
	verifyDSSE(t, att, keyPEM)
}

// executeDeploy runs a deploy step with the custom method and returns the attestation.
func executeDeploy(t *testing.T, engine container.Engine, keyPEM []byte, state *lane.State, packedDigest, imageRef string) *deploy.Attestation {
	t.Helper()
	ctx := context.Background()

	step := &lane.Step{
		Name: "deploy-test",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": imageRef,
			},
			Artifacts: map[string]lane.ArtifactRef{
				"app": {From: "pack.image"},
			},
			Target: lane.DeployTarget{
				Type:        "custom",
				Description: "integration test deploy",
			},
			Attestation: lane.AttestationSpec{
				PreState:  lane.StateCaptureSpec{Required: false},
				PostState: lane.StateCaptureSpec{Required: false},
				Drift:     lane.DriftSpec{Detect: false},
			},
		},
	}

	deployer := &deploy.Deployer{
		Engine:      engine,
		EngineID:    engine.Identity(),
		SigningKey:  keyPEM,
		KeyPassword: nil,
	}

	att, err := deployer.Execute(ctx, step, state)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	if att.DeployID == "" {
		t.Error("empty deploy ID")
	}
	if att.Artifacts["app"] != packedDigest {
		t.Errorf("artifact digest: got %s, want %s", att.Artifacts["app"], packedDigest)
	}
	if valErr := deploy.ValidateAttestation(att); valErr != nil {
		t.Errorf("attestation validation: %v", valErr)
	}
	t.Logf("deploy ID: %s", att.DeployID)
	return att
}

// verifyDSSE checks the DSSE signed envelope on an attestation.
// Verification is inlined here because the production verify function
// lives in a _test.go file (test-only code) and cannot be imported
// cross-package.
func verifyDSSE(t *testing.T, att *deploy.Attestation, keyPEM []byte) {
	t.Helper()

	if att.SignedEnvelope == nil {
		t.Fatal("expected signed envelope, got nil")
	}

	// Decode the DSSE envelope.
	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(att.SignedEnvelope, &envelope); err != nil {
		t.Fatalf("unmarshal DSSE envelope: %v", err)
	}

	// Decode the base64url payload.
	recovered, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode DSSE payload: %v", err)
	}

	// Verify at least one signature against the test public key.
	pubKey := testPublicKeyFrom(t, keyPEM)
	pae := dssePayloadPAE(envelope.PayloadType, recovered)
	digest := sha256.Sum256(pae)

	verified := false
	for _, sig := range envelope.Signatures {
		sigBytes, decErr := base64.StdEncoding.DecodeString(sig.Sig)
		if decErr != nil || len(sigBytes) != 64 {
			continue
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if ecdsa.Verify(pubKey, digest[:], r, s) {
			verified = true
			break
		}
	}
	if !verified {
		t.Fatal("no valid DSSE signature found")
	}

	// Compare recovered payload with the attestation JSON.
	attJSON, marshalErr := json.Marshal(att)
	if marshalErr != nil {
		t.Fatalf("marshal attestation: %v", marshalErr)
	}
	if string(recovered) != string(attJSON) {
		t.Error("recovered DSSE payload does not match attestation JSON")
	}
	if !strings.Contains(string(recovered), att.DeployID) {
		t.Error("deploy ID not found in attestation payload")
	}
}

// dssePayloadPAE constructs DSSE Pre-Authentication Encoding.
func dssePayloadPAE(payloadType string, payload []byte) []byte {
	// "DSSEv1" SP len(type) SP type SP len(payload) SP payload
	var buf strings.Builder
	buf.WriteString("DSSEv1 ")
	buf.WriteString(strconv.Itoa(len(payloadType)))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(len(payload)))
	buf.WriteByte(' ')
	b := []byte(buf.String())
	return append(b, payload...)
}
