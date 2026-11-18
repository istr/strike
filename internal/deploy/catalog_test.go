package deploy_test

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/primitive"
)

func TestGenerateImageSBOM(t *testing.T) {
	fsys := fstest.MapFS{
		"package-lock.json": &fstest.MapFile{
			Data: []byte(`{
				"lockfileVersion": 3,
				"packages": {
					"": {"name": "root", "version": "1.0.0"},
					"node_modules/express": {"version": "4.18.2"}
				}
			}`),
		},
		"var/lib/dpkg/status": &fstest.MapFile{
			Data: []byte("Package: libc6\nVersion: 2.36-9\nArchitecture: amd64\nStatus: install ok installed\n\n"),
		},
	}

	digest := primitive.Digest("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	buildTime := clock.Unix(1700000000, 0).UTC()

	doc, err := deploy.GenerateImageSBOM(fsys, digest, buildTime)
	if err != nil {
		t.Fatalf("deploy.GenerateImageSBOM: %v", err)
	}

	t.Run("cdx_nonempty", func(t *testing.T) {
		if len(doc) == 0 {
			t.Fatal("CycloneDX document is empty")
		}
	})

	t.Run("cdx_contains_npm", func(t *testing.T) {
		if !strings.Contains(string(doc), "pkg:npm/express@4.18.2") {
			t.Error("CycloneDX document missing npm component PURL")
		}
	})

	t.Run("cdx_contains_dpkg", func(t *testing.T) {
		if !strings.Contains(string(doc), "pkg:deb/debian/libc6@2.36-9") {
			t.Error("CycloneDX document missing dpkg component PURL")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		again, err := deploy.GenerateImageSBOM(fsys, digest, buildTime)
		if err != nil {
			t.Fatalf("second generation: %v", err)
		}
		if string(doc) != string(again) {
			t.Error("CycloneDX output is not deterministic")
		}
	})

	t.Run("cdx_valid_json", func(t *testing.T) {
		if !json.Valid(doc) {
			t.Error("CycloneDX document is not valid JSON")
		}
	})

	// The tool entry names strike and the version of strike (ADR-060 D7).
	t.Run("tool_version", func(t *testing.T) {
		var bom struct {
			Metadata struct {
				Tools struct {
					Components []struct {
						Name    string           `json:"name"`
						Version primitive.SemVer `json:"version"`
					} `json:"components"`
				} `json:"tools"`
			} `json:"metadata"`
		}
		if uErr := json.Unmarshal(doc, &bom); uErr != nil {
			t.Fatalf("decode: %v", uErr)
		}
		tools := bom.Metadata.Tools.Components
		if len(tools) != 1 || tools[0].Name != "strike" || tools[0].Version != deploy.StrikeVersion {
			t.Errorf("tools = %+v, want the one entry \"strike\" with the version of strike, %q", tools, deploy.StrikeVersion)
		}
	})
}
