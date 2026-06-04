package deploy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

// AttestationPayloadType is the DSSE payload type for the internal
// collect-model envelope (ADR-013). Retained only for SignAttestation, whose
// production disposition is ADR-040 instruction 3b.
const AttestationPayloadType = "application/vnd.strike.attestation+json"

// InTotoPayloadType is the DSSE payload type for the projected output
// statements (ADR-040 D3). The sealed SLSA provenance, the engine-context
// statement, and the informational statement are standard in-toto Statement v1
// documents; ADR-040 D3 supersedes ADR-013's strike-specific type for them.
const InTotoPayloadType = "application/vnd.in-toto+json"

// SignedStatement is one projected, signed in-toto statement and its Rekor
// transparency-log entry. The Rekor entry is external metadata, never part of
// the signed payload (ADR-013).
type SignedStatement struct {
	Rekor    *lane.RekorEntry `json:"rekor,omitempty"`
	Envelope []byte           `json:"-"`
}

// SignedStatements carries the three projected, signed in-toto statements
// (ADR-040 D3): the sealed SLSA provenance (Layer V), the engine-context
// statement (Layer E), and the informational statement (never gates). Each is
// its own DSSE envelope; each becomes its own OCI referrer when the artifact is
// pushed (instruction 4). Replaces the single SignedEnvelope.
type SignedStatements struct {
	Sealed        SignedStatement
	EngineContext SignedStatement
	Informational SignedStatement
}

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

// signDSSE wraps payload in a signed DSSE envelope with the given payload type:
// base64url (no padding) payload, ECDSA P-256 signature over the PAE. If keyPEM
// is nil, returns an error.
func signDSSE(payload []byte, payloadType string, keyPEM, password []byte) ([]byte, error) {
	if keyPEM == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)
	paeBytes := PAEEncode(payloadType, payload)
	b64sig, keyID, err := executor.SignPayload(paeBytes, keyPEM, password)
	if err != nil {
		return nil, fmt.Errorf("sign dsse: %w", err)
	}
	envelope := DSSEEnvelope{
		PayloadType: payloadType,
		Payload:     b64Payload,
		Signatures:  []DSSESignature{{KeyID: keyID, Sig: b64sig}},
	}
	return json.Marshal(envelope)
}

// SignAttestation wraps internal collect-model JSON in a signed DSSE envelope
// with the strike-specific payload type (ADR-013). Retained for the crossval
// boundary; its production disposition is ADR-040 instruction 3b.
func SignAttestation(attestationJSON, keyPEM, password []byte) ([]byte, error) {
	return signDSSE(attestationJSON, AttestationPayloadType, keyPEM, password)
}

// SignStatement wraps a projected in-toto statement in a signed DSSE envelope
// (ADR-040 D3, in-toto payload type, operator key for now).
func SignStatement(statementJSON, keyPEM, password []byte) ([]byte, error) {
	return signDSSE(statementJSON, InTotoPayloadType, keyPEM, password)
}

// PAEEncode constructs a DSSE Pre-Authentication Encoding.
//
//	"DSSEv1" SP len(type) SP type SP len(payload) SP payload
func PAEEncode(payloadType string, payload []byte) []byte {
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
