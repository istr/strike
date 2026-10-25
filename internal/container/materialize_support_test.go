package container_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestImageLoad_EngineErrorStatus pins that a non-2xx load answer is reported
// by its status and message, not inferred from the shape of the body.
func TestImageLoad_EngineErrorStatus(t *testing.T) {
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(t, w, map[string]any{"cause": "oci-archive: writing blob: digest did not match", "response": 500})
	}))
	_, err := eng.ImageLoad(context.Background(), strings.NewReader("fake-tar-data"))
	if err == nil {
		t.Fatal("ImageLoad() = nil error on a 500 answer")
	}
	for _, want := range []string{"status 500", "digest did not match"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ImageLoad() error = %q, want it to contain %q", err, want)
		}
	}
}

// TestEngineInfoDecoding_Platform pins the host platform fields of /info.
func TestEngineInfoDecoding_Platform(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantOS      string
		wantArch    string
		wantVariant string
	}{
		{
			name: "amd64 without variant",
			body: `{"host": {"os": "linux", "arch": "amd64", "variant": "",
				"security": {"rootless": true}},
				"version": {"APIVersion": "5.4.2", "Version": "5.4.2"}}`,
			wantOS:   "linux",
			wantArch: "amd64",
		},
		{
			name: "arm64 with variant",
			body: `{"host": {"os": "linux", "arch": "arm64", "variant": "v8",
				"security": {"rootless": true}},
				"version": {"APIVersion": "5.4.2", "Version": "5.4.2"}}`,
			wantOS:      "linux",
			wantArch:    "arm64",
			wantVariant: "v8",
		},
		{
			name: "missing host fields decode empty",
			body: `{"host": {}, "version": {"APIVersion": "5.4.2", "Version": "5.4.2"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, infoHandler(t, tt.body))
			rt := fetchRuntime(t, eng)
			if rt.OS != tt.wantOS || rt.Arch != tt.wantArch || rt.Variant != tt.wantVariant {
				t.Errorf("platform = %s/%s/%q, want %s/%s/%q",
					rt.OS, rt.Arch, rt.Variant, tt.wantOS, tt.wantArch, tt.wantVariant)
			}
		})
	}
}
