package deploy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/istr/strike/internal/deploy"
)

// verifyAttestationSignature verifies a DSSE-wrapped attestation.
// publicKeyPEM is the PEM-encoded public key (PKIX/SPKI format).
// Returns the decoded attestation JSON payload on success.
//
// This function lives in a _test.go file because it is only used by tests.
// Production verification is not yet wired.
func verifyAttestationSignature(envelopeJSON, publicKeyPEM []byte) ([]byte, error) {
	var envelope deploy.DSSEEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal DSSE envelope: %w", err)
	}

	// Decode the base64url payload to recover the original attestation JSON.
	decoded, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	// Reconstruct the PAE that was signed.
	paeBytes := deploy.PAEEncode(envelope.PayloadType, decoded)
	digest := sha256.Sum256(paeBytes)

	pubKey, err := loadVerifyKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	for _, sig := range envelope.Signatures {
		sigBytes, decErr := base64.StdEncoding.DecodeString(sig.Sig)
		if decErr != nil {
			continue
		}
		if len(sigBytes) != 64 {
			continue
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if ecdsa.Verify(pubKey, digest[:], r, s) {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("no valid signature found")
}

// loadVerifyKey parses an ECDSA public key from PEM.
func loadVerifyKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not ECDSA", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("public key curve is %v, expected P-256", ecPub.Curve)
	}
	return ecPub, nil
}
