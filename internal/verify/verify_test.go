package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/verify"
)

// keyPair returns a fresh ECDSA P-256 private-key PEM (PKCS#8) and the
// matching public-key PEM (PKIX).
func keyPair(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM
}

func TestEnvelope_RoundTrip(t *testing.T) {
	privPEM, pubPEM := keyPair(t)
	attestation := []byte(`{"sealed":{"lane_id":"test-lane"}}`)

	envelopeJSON, err := deploy.SignAttestation(attestation, privPEM, nil)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	res, err := verify.Envelope(envelopeJSON, pubPEM)
	if err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	if string(res.AttestationJSON) != string(attestation) {
		t.Errorf("decoded payload = %q, want %q", res.AttestationJSON, attestation)
	}
}

func TestEnvelope_WrongKey(t *testing.T) {
	privPEM, _ := keyPair(t)
	_, otherPubPEM := keyPair(t)

	envelopeJSON, err := deploy.SignAttestation([]byte(`{"sealed":{"lane_id":"x"}}`), privPEM, nil)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	_, err = verify.Envelope(envelopeJSON, otherPubPEM)
	if !errors.Is(err, verify.ErrNoValidSignature) {
		t.Errorf("expected ErrNoValidSignature, got %v", err)
	}
}

func TestEnvelope_WrongPayloadType(t *testing.T) {
	_, pubPEM := keyPair(t)
	// Hand-build an envelope with a foreign payload type.
	env := deploy.DSSEEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "e30", // base64url of "{}"
		Signatures:  []deploy.DSSESignature{{KeyID: "k", Sig: ""}},
	}
	envelopeJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = verify.Envelope(envelopeJSON, pubPEM)
	if !errors.Is(err, verify.ErrPayloadType) {
		t.Errorf("expected ErrPayloadType, got %v", err)
	}
}

func TestEnvelope_BadPEM(t *testing.T) {
	privPEM, _ := keyPair(t)
	envelopeJSON, err := deploy.SignAttestation([]byte(`{}`), privPEM, nil)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	if _, err := verify.Envelope(envelopeJSON, []byte("not a pem")); err == nil {
		t.Error("expected error for malformed public key PEM")
	}
}
