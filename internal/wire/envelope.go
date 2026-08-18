package wire

import (
	"bytes"
	"strconv"
)

// PayloadType is the DSSE payload type for strike's projected in-toto
// statements (ADR-040 D3). The sealed SLSA provenance, the engine-context
// statement, and the informational statement are standard in-toto Statement v1
// documents; ADR-040 D3 supersedes ADR-013's strike-specific type for them.
const PayloadType = "application/vnd.in-toto+json"

// MediaType is the only sigstore bundle media type strike emits and the only
// one the verifier accepts (v0.3).
const MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

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
