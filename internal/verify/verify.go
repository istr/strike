// Package verify implements offline verification of strike deploy
// attestations. It is the consumer counterpart to internal/deploy's
// producer side: deploy signs and submits, verify checks.
//
// This file provides the core: parse a DSSE envelope, guard its payload
// type, and verify the ECDSA P-256 signature over the DSSE
// pre-authentication encoding. The decoded, signature-checked attestation
// JSON is returned for the caller to parse and apply trust-layer semantics.
//
// Rekor verification and the Layer-V anchor cross-check are separate
// concerns added in later instructions; this file performs neither. The
// signed payload never contains sealed.rekor (the producer sets it after
// signing), so no field stripping is performed here -- the signature is
// checked over the payload as carried in the envelope.
package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/istr/strike/internal/deploy"
)

// ErrPayloadType is returned when the DSSE envelope carries a payload type
// other than the strike attestation type. The payload-type URI is the
// cross-protocol-confusion guard; a mismatch is a hard failure, not a
// best-effort fallback.
var ErrPayloadType = errors.New("verify: unexpected DSSE payload type")

// ErrNoValidSignature is returned when no signature in the envelope verifies
// against the supplied public key.
var ErrNoValidSignature = errors.New("verify: no valid signature found")

// SignatureResult is the outcome of envelope signature verification: the
// decoded attestation JSON (the DSSE payload) and the keyid of the signature
// that verified.
type SignatureResult struct {
	KeyID           string
	AttestationJSON []byte
}

// Envelope verifies the DSSE envelope in envelopeJSON against publicKeyPEM
// and returns the decoded attestation JSON on success.
//
// It enforces the strike attestation payload type, reconstructs the DSSE
// pre-authentication encoding, and checks the ECDSA P-256 signature over
// sha256(PAE). It does not parse the attestation, verify Rekor, or check
// any anchor: those are the caller's and later steps' concerns.
func Envelope(envelopeJSON, publicKeyPEM []byte) (*SignatureResult, error) {
	var envelope deploy.DSSEEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("verify: unmarshal DSSE envelope: %w", err)
	}

	if envelope.PayloadType != deploy.AttestationPayloadType {
		return nil, fmt.Errorf("%w: got %q, want %q",
			ErrPayloadType, envelope.PayloadType, deploy.AttestationPayloadType)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("verify: decode DSSE payload: %w", err)
	}

	pubKey, err := parseVerifyKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	paeBytes := deploy.PAEEncode(envelope.PayloadType, decoded)
	digest := sha256.Sum256(paeBytes)

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
			return &SignatureResult{AttestationJSON: decoded, KeyID: sig.KeyID}, nil
		}
	}
	return nil, ErrNoValidSignature
}

// parseVerifyKey parses an ECDSA P-256 public key from PEM (PKIX/SPKI).
// The curve is checked: strike signs with P-256 only (ADR-008), so any
// other curve is a rejected input, not a verification attempt.
func parseVerifyKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("verify: no PEM block found in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("verify: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("verify: public key is %T, not ECDSA", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("verify: public key curve is %v, expected P-256", ecPub.Curve)
	}
	return ecPub, nil
}
