package deploy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/deploy"
)

// generateTestKeyPEM creates a fresh ECDSA P-256 key pair and returns
// the private key PEM and the public key PEM.
func generateTestKeyPEM(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

func TestSignAttestation_RoundTrip(t *testing.T) {
	privPEM, pubPEM := generateTestKeyPEM(t)
	attestation := []byte(`{"deploy_id":"test123","timestamp":"2024-01-01T00:00:00Z"}`)

	envelopeJSON, err := deploy.SignAttestation(attestation, privPEM, nil)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	// Verify the envelope structure.
	var env deploy.DSSEEnvelope
	if unmarshalErr := json.Unmarshal(envelopeJSON, &env); unmarshalErr != nil {
		t.Fatalf("unmarshal envelope: %v", unmarshalErr)
	}
	if env.PayloadType != deploy.AttestationPayloadType {
		t.Errorf("payloadType = %q, want %q", env.PayloadType, deploy.AttestationPayloadType)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("got %d signatures, want 1", len(env.Signatures))
	}
	if env.Signatures[0].KeyID == "" {
		t.Error("keyid is empty")
	}

	// Verify and recover payload.
	recovered, err := verifyAttestationSignature(envelopeJSON, pubPEM)
	if err != nil {
		t.Fatalf("VerifyAttestationSignature: %v", err)
	}
	if string(recovered) != string(attestation) {
		t.Errorf("recovered payload = %q, want %q", recovered, attestation)
	}
}

func TestSignAttestation_TamperedPayload(t *testing.T) {
	privPEM, pubPEM := generateTestKeyPEM(t)
	attestation := []byte(`{"deploy_id":"test123"}`)

	envelopeJSON, err := deploy.SignAttestation(attestation, privPEM, nil)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	// Tamper with the payload field.
	var raw map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(envelopeJSON, &raw); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	// Re-encode with a different payload.
	tampered := base64.RawURLEncoding.EncodeToString([]byte(`{"deploy_id":"TAMPERED"}`))
	tamperedPayload, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	raw["payload"] = tamperedPayload
	tamperedEnvelope, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}

	if _, verifyErr := verifyAttestationSignature(tamperedEnvelope, pubPEM); verifyErr == nil {
		t.Error("expected verification to fail for tampered payload")
	}
}

func TestSignAttestation_WrongKey(t *testing.T) {
	privA, _ := generateTestKeyPEM(t)
	_, pubB := generateTestKeyPEM(t)

	attestation := []byte(`{"deploy_id":"test123"}`)
	envelopeJSON, err := deploy.SignAttestation(attestation, privA, nil)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	if _, verifyErr := verifyAttestationSignature(envelopeJSON, pubB); verifyErr == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestSignAttestation_NilKey(t *testing.T) {
	if _, err := deploy.SignAttestation([]byte(`{}`), nil, nil); err == nil {
		t.Error("expected error for nil signing key")
	}
}

func TestPAEEncode(t *testing.T) {
	// The PAE function is not exported, but we can test it indirectly
	// through SignAttestation + VerifyAttestationSignature round-trip.
	// The DSSE spec says PAE is:
	//   "DSSEv1" SP len(type) SP type SP len(payload) SP payload
	//
	// We verify correctness by ensuring that a valid signature produced
	// by SignAttestation can be verified -- which requires PAE to be
	// constructed identically on both sides.
	privPEM, pubPEM := generateTestKeyPEM(t)

	tests := []struct {
		name        string
		attestation []byte
	}{
		{"empty", []byte(`{}`)},
		{"minimal", []byte(`{"a":"b"}`)},
		{"unicode", []byte(`{"name":"José"}`)},
		{"large", make([]byte, 4096)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := deploy.SignAttestation(tt.attestation, privPEM, nil)
			if err != nil {
				t.Fatalf("SignAttestation: %v", err)
			}
			recovered, err := verifyAttestationSignature(env, pubPEM)
			if err != nil {
				t.Fatalf("VerifyAttestationSignature: %v", err)
			}
			if string(recovered) != string(tt.attestation) {
				t.Error("round-trip payload mismatch")
			}
		})
	}
}

// --------------------------------------------------------------------------.

type signAttestationVector struct {
	Boundary    string                  `json:"boundary"`
	Description string                  `json:"description"`
	Inputs      signAttestationInputs   `json:"inputs"`
	Expected    signAttestationExpected `json:"expected"`
}

type signAttestationInputs struct {
	Password        *string `json:"password"`
	AttestationJSON string  `json:"attestation_json"`
	KeyPEM          string  `json:"key_pem,omitempty"`
}

type signAttestationExpected struct {
	Verify              signAttestationVerify `json:"verify"`
	PayloadType         string                `json:"payload_type"`
	PayloadMatchesInput bool                  `json:"payload_matches_input"`
}

type signAttestationVerify struct {
	Algorithm          string `json:"algorithm"`
	PublicKeyDERBase64 string `json:"public_key_der_base64,omitempty"`
}

func TestSignAttestation_Golden(t *testing.T) {
	path := filepath.Join(crossvalDir, "sign", "attestation_dsse.json")
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a hardcoded test constant, not user input
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vec signAttestationVector
	if unmarshalErr := json.Unmarshal(data, &vec); unmarshalErr != nil {
		t.Fatalf("unmarshal vector: %v", unmarshalErr)
	}

	// Generate an ephemeral key for this test run.
	privPEM, pubPEM := generateTestKeyPEM(t)
	var password []byte
	if vec.Inputs.Password != nil {
		password = []byte(*vec.Inputs.Password)
	}
	attestationJSON := []byte(vec.Inputs.AttestationJSON)

	envelopeJSON, err := deploy.SignAttestation(attestationJSON, privPEM, password)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	// Verify envelope structure.
	var env deploy.DSSEEnvelope
	if unmarshalErr := json.Unmarshal(envelopeJSON, &env); unmarshalErr != nil {
		t.Fatalf("unmarshal envelope: %v", unmarshalErr)
	}
	if env.PayloadType != vec.Expected.PayloadType {
		t.Errorf("payloadType = %q, want %q", env.PayloadType, vec.Expected.PayloadType)
	}

	// Verify payload matches input.
	if vec.Expected.PayloadMatchesInput {
		decoded, decErr := base64.RawURLEncoding.DecodeString(env.Payload)
		if decErr != nil {
			t.Fatalf("decode payload: %v", decErr)
		}
		if string(decoded) != vec.Inputs.AttestationJSON {
			t.Errorf("decoded payload does not match input attestation JSON")
		}
	}

	// Verify signature with the ephemeral public key.
	recovered, verifyErr := verifyAttestationSignature(envelopeJSON, pubPEM)
	if verifyErr != nil {
		t.Fatalf("VerifyAttestationSignature: %v", verifyErr)
	}
	if string(recovered) != vec.Inputs.AttestationJSON {
		t.Errorf("recovered payload does not match input")
	}
}
