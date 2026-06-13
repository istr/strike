package deploy

import (
	"bytes"
	"strconv"
)

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
