package deploy_test

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"
)

// writeJSON encodes v as JSON to w, failing the test on error.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("test handler: encode JSON: %v", err)
	}
}

// mustWrite writes data to w, failing the test on error.
func mustWrite(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatalf("test handler: write: %v", err)
	}
}

// streamFrame builds a Podman multiplexed log frame (header + payload).
// stream: 1=stdout, 2=stderr.
func streamFrame(stream byte, payload []byte) []byte {
	frame := make([]byte, 8+len(payload))
	frame[0] = stream
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload))) // #nosec G115 -- test data is always small
	copy(frame[8:], payload)
	return frame
}
