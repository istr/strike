package deploy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/istr/strike/internal/executor"
)

// AttestationPayloadType is the DSSE payload type for strike attestations.
const AttestationPayloadType = "application/vnd.strike.attestation+json"

// DSSEEnvelope is a Dead Simple Signing Envelope (in-toto v1).
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature is one signature within a DSSE envelope.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// SignAttestation wraps attestation JSON in a signed DSSE envelope.
// Returns the envelope JSON. If keyPEM is nil, returns an error.
func SignAttestation(attestationJSON, keyPEM, password []byte) ([]byte, error) {
	if keyPEM == nil {
		return nil, fmt.Errorf("signing key is required")
	}

	// Base64url-encode (no padding) the attestation as the envelope payload.
	b64Payload := base64.RawURLEncoding.EncodeToString(attestationJSON)

	// Construct PAE (Pre-Authentication Encoding) over the raw payload.
	paeBytes := paeEncode(AttestationPayloadType, attestationJSON)

	b64sig, keyID, err := executor.SignPayload(paeBytes, keyPEM, password)
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}

	envelope := DSSEEnvelope{
		PayloadType: AttestationPayloadType,
		Payload:     b64Payload,
		Signatures:  []DSSESignature{{KeyID: keyID, Sig: b64sig}},
	}
	return json.Marshal(envelope)
}

// paeEncode constructs a DSSE Pre-Authentication Encoding.
//
//	"DSSEv1" SP len(type) SP type SP len(payload) SP payload
func paeEncode(payloadType string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("DSSEv1 ")
	buf.WriteString(strconv.Itoa(len(payloadType)))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(len(payload)))
	buf.WriteByte(' ')
	buf.Write(payload)
	return buf.Bytes()
}
