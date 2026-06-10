package deploy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/istr/strike/internal/executor"
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

// SignedStatement is one projected in-toto statement, signed keylessly and
// carried as a sigstore v0.3 bundle (ADR-040 D2). The bundle subsumes the
// transparency proof (inclusion proof, checkpoint, RFC3161 timestamp), so
// no separate Rekor entry is recorded.
type SignedStatement struct {
	Bundle []byte `json:"-"`
}

// SignedStatements carries the three projected, keylessly signed in-toto
// statements (ADR-040 D3): the sealed SLSA provenance (Layer V), the
// engine-context statement (Layer E), and the informational statement (never
// gates). Each is its own sigstore bundle; on registry deploys each becomes
// its own OCI referrer of the pushed manifest digest. Replaces the single
// SignedEnvelope.
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
