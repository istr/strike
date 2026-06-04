package executor_test

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/executor"
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

	digest := "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	buildTime := clock.Unix(1700000000, 0).UTC()

	cdxDoc, spdxDoc, err := executor.GenerateImageSBOM(fsys, digest, buildTime)
	if err != nil {
		t.Fatalf("executor.GenerateImageSBOM: %v", err)
	}

	t.Run("cdx_nonempty", func(t *testing.T) {
		if len(cdxDoc) == 0 {
			t.Fatal("CycloneDX document is empty")
		}
	})

	t.Run("spdx_nonempty", func(t *testing.T) {
		if len(spdxDoc) == 0 {
			t.Fatal("SPDX document is empty")
		}
	})

	t.Run("cdx_contains_npm", func(t *testing.T) {
		if !strings.Contains(string(cdxDoc), "pkg:npm/express@4.18.2") {
			t.Error("CycloneDX document missing npm component PURL")
		}
	})

	t.Run("spdx_contains_dpkg", func(t *testing.T) {
		if !strings.Contains(string(spdxDoc), "pkg:deb/debian/libc6@2.36-9") {
			t.Error("SPDX document missing dpkg component PURL")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		cdx2, spdx2, err := executor.GenerateImageSBOM(fsys, digest, buildTime)
		if err != nil {
			t.Fatalf("second generation: %v", err)
		}
		if string(cdxDoc) != string(cdx2) {
			t.Error("CycloneDX output is not deterministic")
		}
		if string(spdxDoc) != string(spdx2) {
			t.Error("SPDX output is not deterministic")
		}
	})

	t.Run("cdx_valid_json", func(t *testing.T) {
		if !json.Valid(cdxDoc) {
			t.Error("CycloneDX document is not valid JSON")
		}
	})

	t.Run("spdx_valid_json", func(t *testing.T) {
		if !json.Valid(spdxDoc) {
			t.Error("SPDX document is not valid JSON")
		}
	})
}
