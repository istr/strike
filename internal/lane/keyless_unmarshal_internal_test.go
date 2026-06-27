package lane

import (
	"strings"
	"testing"
)

func TestUnmarshalKeyless(t *testing.T) {
	const fp = `{"type":"certFingerprint","fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`
	const eps = `"endpoints": {
		"fulcio": {"url": "https://fulcio.example:5555", "trust": ` + fp + `},
		"rekor":  {"url": "https://rekor.example:3003", "trust": ` + fp + `},
		"tsa":    {"url": "https://tsa.example:3004", "trust": ` + fp + `}
	}`
	const ref = `"localhost:5555/tr@sha256:abababababababababababababababababababababababababababababababab"`

	tests := []struct {
		name       string
		in         string
		wantErr    string
		wantInline bool
		wantRef    bool
	}{
		{name: "endpoints only", in: `{` + eps + `}`},
		{name: "inline trust root", in: `{` + eps + `, "trustRoot": {"mediaType": "x"}}`, wantInline: true},
		{name: "ref trust root", in: `{` + eps + `, "trustRootRef": ` + ref + `}`, wantRef: true},
		{
			name:    "both rejected",
			in:      `{` + eps + `, "trustRoot": {}, "trustRootRef": ` + ref + `}`,
			wantErr: "trustRoot and trustRootRef are mutually exclusive",
		},
		{name: "missing tsa", in: `{"endpoints": {
			"fulcio": {"url": "https://f.example", "trust": ` + fp + `},
			"rekor":  {"url": "https://r.example", "trust": ` + fp + `}
		}}`, wantErr: "keyless: tsa required"},
		{name: "missing trust", in: `{"endpoints": {
			"fulcio": {"url": "https://f.example"},
			"rekor":  {"url": "https://r.example", "trust": ` + fp + `},
			"tsa":    {"url": "https://t.example", "trust": ` + fp + `}
		}}`, wantErr: "keyless fulcio: trust required"},
		{name: "unknown trust type", in: `{"endpoints": {
			"fulcio": {"url": "https://f.example", "trust": {"type": "system_ca"}},
			"rekor":  {"url": "https://r.example", "trust": ` + fp + `},
			"tsa":    {"url": "https://t.example", "trust": ` + fp + `}
		}}`, wantErr: "keyless fulcio:"},
		{name: "bad keyless json", in: `{`, wantErr: "decode keyless"},
		{name: "bad trustRoot json", in: `{` + eps + `, "trustRoot": 5}`, wantErr: "decode trustRoot"},
		{name: "bad trustRootRef json", in: `{` + eps + `, "trustRootRef": 5}`, wantErr: "decode trustRootRef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalKeyless([]byte(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshalKeyless: %v", err)
			}
			if got.Endpoints.Fulcio.Address.URL() != "https://fulcio.example:5555" {
				t.Errorf("fulcio url = %q", got.Endpoints.Fulcio.Address.URL())
			}
			if got.Endpoints.TSA.Trust == nil || got.Endpoints.TSA.Trust.TrustType() != "certFingerprint" {
				t.Errorf("tsa trust not dispatched: %#v", got.Endpoints.TSA.Trust)
			}
			if tt.wantInline && (got.TrustRoot == nil || got.TrustRoot.MediaType != "x") {
				t.Errorf("trustRoot not parsed: %#v", got.TrustRoot)
			}
			if !tt.wantInline && got.TrustRoot != nil {
				t.Errorf("unexpected trustRoot: %#v", got.TrustRoot)
			}
			if tt.wantRef && got.TrustRootRef == "" {
				t.Errorf("trustRootRef empty")
			}
			if !tt.wantRef && got.TrustRootRef != "" {
				t.Errorf("unexpected trustRootRef: %q", got.TrustRootRef)
			}
		})
	}
}
