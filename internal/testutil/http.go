package testutil

import (
	"encoding/json"
	"net/http"
	"testing"
)

// WriteBody writes body to w and reports errors via t.Errorf.
func WriteBody(t *testing.T, w http.ResponseWriter, body []byte) {
	t.Helper()
	if _, err := w.Write(body); err != nil {
		t.Errorf("write response body: %v", err)
	}
}

// WriteJSON JSON-encodes v into w and reports errors via t.Errorf.
func WriteJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
