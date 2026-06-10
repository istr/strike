package lane

import (
	"strings"
	"testing"
)

func TestUnmarshalKeylessEndpoints(t *testing.T) {
	const fp = `{"mode":"cert_fingerprint","fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`
	valid := `{
		"fulcio": {"url": "https://fulcio.example:5555", "trust": ` + fp + `},
		"rekor":  {"url": "https://rekor.example:3003", "trust": ` + fp + `},
		"tsa":    {"url": "https://tsa.example:3004", "trust": ` + fp + `}
	}`

	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"valid", valid, ""},
		{"missing tsa", `{
			"fulcio": {"url": "https://f.example", "trust": ` + fp + `},
			"rekor":  {"url": "https://r.example", "trust": ` + fp + `}
		}`, "keyless: tsa required"},
		{"missing trust", `{
			"fulcio": {"url": "https://f.example"},
			"rekor":  {"url": "https://r.example", "trust": ` + fp + `},
			"tsa":    {"url": "https://t.example", "trust": ` + fp + `}
		}`, "keyless fulcio: trust required"},
		{"unknown trust mode", `{
			"fulcio": {"url": "https://f.example", "trust": {"mode": "system_ca"}},
			"rekor":  {"url": "https://r.example", "trust": ` + fp + `},
			"tsa":    {"url": "https://t.example", "trust": ` + fp + `}
		}`, "keyless fulcio:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalKeylessEndpoints([]byte(tt.in))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unmarshalKeylessEndpoints: %v", err)
				}
				if got.Fulcio.URL != "https://fulcio.example:5555" {
					t.Errorf("fulcio url = %q", got.Fulcio.URL)
				}
				if got.TSA.Trust == nil || got.TSA.Trust.TrustMode() != "cert_fingerprint" {
					t.Errorf("tsa trust not dispatched: %#v", got.TSA.Trust)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
