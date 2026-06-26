package integration_test

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

func TestPackSBOM(t *testing.T) {
	engine := testutil.RequireEngine(t)

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// Build a Go binary so the flattened image has go-buildinfo.
	binPath := buildTestBinary(t, engine)

	// Pack with config_files that inject an npm lockfile and dpkg status
	// into the assembled image, exercising all three cataloger sources.
	lockfileJSON := `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "root", "version": "1.0.0"},
			"node_modules/express": {"version": "4.18.2"}
		}
	}`
	dpkgStatus := "Package: libc6\nVersion: 2.36-9\nArchitecture: amd64\nStatus: install ok installed\n\n"

	outDir := t.TempDir()
	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		t.Fatal(err)
	}
	defer testutil.CloseLog(t, outRoot, "sbom test outRoot")

	result, err := executor.Pack(executor.PackOpts{
		Spec: &lane.PackSpec{
			Base: primitive.ImageRef(staticBase),
			Files: []lane.PackFile{
				{From: lane.OutputRef{Step: "build", Output: "app"}, Dest: "/app", Mode: 0o755},
			},
			Config: &lane.ImageConfig{
				Entrypoint: []string{"/app"},
				User:       lane.Ptr("65534:65534"),
			},
			ConfigFiles: map[string]lane.FileEntry{
				"/package-lock.json": {
					Content: lockfileJSON,
					Mode:    0o644,
				},
				"/var/lib/dpkg/status": {
					Content: dpkgStatus,
					Mode:    0o644,
				},
			},
		},
		InputPaths: map[string]string{"/app": binPath},
		OutputRoot: outRoot,
		OutputName: "image.tar",
	})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	imgDigest := result.Digest.String()
	t.Logf("image digest: %s", imgDigest)

	// Extract the OCI layout tar and inspect its contents.
	tarFile, err := outRoot.Open("image.tar")
	if err != nil {
		t.Fatalf("open image.tar: %v", err)
	}
	tarData, err := io.ReadAll(tarFile)
	closer.Warn(tarFile, "sbom test tar")
	if err != nil {
		t.Fatalf("read image.tar: %v", err)
	}

	layoutDir := t.TempDir()
	layoutRoot, err := os.OpenRoot(layoutDir)
	if err != nil {
		t.Fatalf("open layout root: %v", err)
	}
	defer testutil.CloseLog(t, layoutRoot, "sbom test layoutRoot")

	if extractErr := regtest.ExtractTar(tarData, layoutRoot); extractErr != nil {
		t.Fatalf("extract layout: %v", extractErr)
	}

	lp, err := layout.FromPath(layoutDir)
	if err != nil {
		t.Fatalf("open layout: %v", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("read index manifest: %v", err)
	}

	// Identify SBOM referrers by reading each non-main manifest's layers.
	var cdxData, spdxData []byte
	var sbomCount int
	for _, desc := range manifest.Manifests {
		if _, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
			continue // main image
		}
		img, imgErr := idx.Image(desc.Digest)
		if imgErr != nil {
			t.Fatalf("read image %s: %v", desc.Digest, imgErr)
		}
		layers, layersErr := img.Layers()
		if layersErr != nil || len(layers) == 0 {
			continue
		}
		mt, mtErr := layers[0].MediaType()
		if mtErr != nil {
			continue
		}
		switch string(mt) {
		case "application/vnd.cyclonedx+json":
			sbomCount++
			cdxData = readLayer(t, layers[0])
		case "application/spdx+json":
			sbomCount++
			spdxData = readLayer(t, layers[0])
		}
	}

	t.Run("two_sbom_referrers", func(t *testing.T) {
		if sbomCount != 2 {
			t.Fatalf("expected 2 SBOM referrers, got %d", sbomCount)
		}
	})

	t.Run("cdx_subject_is_artifact_digest", func(t *testing.T) {
		var doc struct {
			Metadata struct {
				Component struct {
					Name string `json:"name"`
				} `json:"component"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(cdxData, &doc); err != nil {
			t.Fatalf("unmarshal cdx: %v", err)
		}
		if doc.Metadata.Component.Name != imgDigest {
			t.Errorf("cdx subject = %q, want %q", doc.Metadata.Component.Name, imgDigest)
		}
	})

	t.Run("cdx_contains_npm", func(t *testing.T) {
		if !strings.Contains(string(cdxData), "pkg:npm/express@4.18.2") {
			t.Error("CycloneDX missing npm component")
		}
	})

	t.Run("cdx_contains_dpkg", func(t *testing.T) {
		if !strings.Contains(string(cdxData), "pkg:deb/debian/libc6@2.36-9") {
			t.Error("CycloneDX missing dpkg component")
		}
	})

	t.Run("cdx_contains_golang", func(t *testing.T) {
		if !strings.Contains(string(cdxData), "pkg:golang/") {
			t.Error("CycloneDX missing Go module component")
		}
	})

	t.Run("spdx_contains_npm", func(t *testing.T) {
		if !strings.Contains(string(spdxData), "pkg:npm/express@4.18.2") {
			t.Error("SPDX missing npm component")
		}
	})

	t.Run("spdx_contains_dpkg", func(t *testing.T) {
		if !strings.Contains(string(spdxData), "pkg:deb/debian/libc6@2.36-9") {
			t.Error("SPDX missing dpkg component")
		}
	})

	t.Run("deterministic_sbom", func(t *testing.T) {
		outDir2 := t.TempDir()
		outRoot2, openErr := os.OpenRoot(outDir2)
		if openErr != nil {
			t.Fatalf("open root 2: %v", openErr)
		}
		defer testutil.CloseLog(t, outRoot2, "sbom test outRoot2")

		_, err := executor.Pack(executor.PackOpts{
			Spec: &lane.PackSpec{
				Base: primitive.ImageRef(staticBase),
				Files: []lane.PackFile{
					{From: lane.OutputRef{Step: "build", Output: "app"}, Dest: "/app", Mode: 0o755},
				},
				Config: &lane.ImageConfig{
					Entrypoint: []string{"/app"},
					User:       lane.Ptr("65534:65534"),
				},
				ConfigFiles: map[string]lane.FileEntry{
					"/package-lock.json": {
						Content: lockfileJSON,
						Mode:    0o644,
					},
					"/var/lib/dpkg/status": {
						Content: dpkgStatus,
						Mode:    0o644,
					},
				},
			},
			InputPaths: map[string]string{"/app": binPath},
			OutputRoot: outRoot2,
			OutputName: "image.tar",
		})
		if err != nil {
			t.Fatalf("pack (second run): %v", err)
		}

		tarFile2, err := outRoot2.Open("image.tar")
		if err != nil {
			t.Fatalf("open image.tar: %v", err)
		}
		tarData2, err := io.ReadAll(tarFile2)
		closer.Warn(tarFile2, "sbom test tar2")
		if err != nil {
			t.Fatalf("read image.tar: %v", err)
		}

		layoutDir2 := t.TempDir()
		layoutRoot2, err := os.OpenRoot(layoutDir2)
		if err != nil {
			t.Fatalf("open layout root 2: %v", err)
		}
		defer testutil.CloseLog(t, layoutRoot2, "sbom test layoutRoot2")

		if extractErr := regtest.ExtractTar(tarData2, layoutRoot2); extractErr != nil {
			t.Fatalf("extract layout 2: %v", extractErr)
		}

		lp2, err := layout.FromPath(layoutDir2)
		if err != nil {
			t.Fatalf("open layout 2: %v", err)
		}
		idx2, err := lp2.ImageIndex()
		if err != nil {
			t.Fatalf("read index 2: %v", err)
		}
		manifest2, err := idx2.IndexManifest()
		if err != nil {
			t.Fatalf("read index manifest 2: %v", err)
		}

		var cdxData2, spdxData2 []byte
		for _, desc := range manifest2.Manifests {
			if _, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
				continue
			}
			img, imgErr := idx2.Image(desc.Digest)
			if imgErr != nil {
				continue
			}
			layers, layersErr := img.Layers()
			if layersErr != nil || len(layers) == 0 {
				continue
			}
			mt, mtErr := layers[0].MediaType()
			if mtErr != nil {
				continue
			}
			switch string(mt) {
			case "application/vnd.cyclonedx+json":
				cdxData2 = readLayer(t, layers[0])
			case "application/spdx+json":
				spdxData2 = readLayer(t, layers[0])
			}
		}

		if string(cdxData) != string(cdxData2) {
			t.Error("CycloneDX output is not deterministic across packs")
		}
		if string(spdxData) != string(spdxData2) {
			t.Error("SPDX output is not deterministic across packs")
		}
	})
}

// readLayer reads the uncompressed content of an OCI layer.
func readLayer(t *testing.T, layer v1.Layer) []byte {
	t.Helper()
	rc, err := layer.Uncompressed()
	if err != nil {
		t.Fatalf("uncompressed layer: %v", err)
	}
	defer closer.Warn(rc, "readLayer")
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read layer: %v", err)
	}
	return data
}
