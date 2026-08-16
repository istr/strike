package registry_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
)

// imageFromRegtestTar builds a minimal valid image via regtest and opens it
// as a v1.Image, the original against which round trips are compared.
func imageFromRegtestTar(t *testing.T) v1.Image {
	t.Helper()
	tarBytes, _, err := regtest.BuildImageTar("hello.txt", []byte("hello"))
	if err != nil {
		t.Fatalf("BuildImageTar: %v", err)
	}
	img, err := registry.ImageFromOCITar(tarBytes)
	if err != nil {
		t.Fatalf("ImageFromOCITar: %v", err)
	}
	return img
}

func TestOCITarFromImage_RoundTrip(t *testing.T) {
	img := imageFromRegtestTar(t)
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	wantConfig, err := img.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}
	wantCfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	data, err := registry.OCITarFromImage(img, nil)
	if err != nil {
		t.Fatalf("OCITarFromImage: %v", err)
	}
	got, err := registry.ImageFromOCITar(data)
	if err != nil {
		t.Fatalf("ImageFromOCITar: %v", err)
	}

	gotDigest, err := got.Digest()
	if err != nil {
		t.Fatalf("round-trip digest: %v", err)
	}
	if gotDigest != wantDigest {
		t.Errorf("manifest digest = %s, want %s", gotDigest, wantDigest)
	}
	gotConfig, err := got.ConfigName()
	if err != nil {
		t.Fatalf("round-trip config digest: %v", err)
	}
	if gotConfig != wantConfig {
		t.Errorf("config digest = %s, want %s", gotConfig, wantConfig)
	}
	gotCfg, err := got.ConfigFile()
	if err != nil {
		t.Fatalf("round-trip config: %v", err)
	}
	if len(gotCfg.RootFS.DiffIDs) != len(wantCfg.RootFS.DiffIDs) {
		t.Fatalf("diff_ids length = %d, want %d", len(gotCfg.RootFS.DiffIDs), len(wantCfg.RootFS.DiffIDs))
	}
	for i, want := range wantCfg.RootFS.DiffIDs {
		if gotCfg.RootFS.DiffIDs[i] != want {
			t.Errorf("diff_ids[%d] = %s, want %s", i, gotCfg.RootFS.DiffIDs[i], want)
		}
	}
}

func TestOCITarFromImage_Deterministic(t *testing.T) {
	img := imageFromRegtestTar(t)
	first, err := registry.OCITarFromImage(img, nil)
	if err != nil {
		t.Fatalf("first serialization: %v", err)
	}
	second, err := registry.OCITarFromImage(img, nil)
	if err != nil {
		t.Fatalf("second serialization: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("the same image serialized to different bytes")
	}
}

func TestOCITarFromImage_CarriesIndexAnnotations(t *testing.T) {
	img := imageFromRegtestTar(t)
	const key = "org.opencontainers.image.ref.name"
	data, err := registry.OCITarFromImage(img, map[string]string{key: "sha256:test"})
	if err != nil {
		t.Fatalf("OCITarFromImage: %v", err)
	}

	var indexBytes []byte
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read layout tar: %v", nextErr)
		}
		if path.Clean(hdr.Name) == "index.json" {
			content, readErr := io.ReadAll(tr)
			if readErr != nil {
				t.Fatalf("read index.json: %v", readErr)
			}
			indexBytes = content
		}
	}
	if indexBytes == nil {
		t.Fatal("index.json not found in layout tar")
	}

	var idx v1.IndexManifest
	if uErr := json.Unmarshal(indexBytes, &idx); uErr != nil {
		t.Fatalf("parse index.json: %v", uErr)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("index carries %d descriptors, want 1", len(idx.Manifests))
	}
	if got := idx.Manifests[0].Annotations[key]; got != "sha256:test" {
		t.Errorf("descriptor annotation %s = %q, want %q", key, got, "sha256:test")
	}
}

func TestImageFromOCITar_RejectsGarbage(t *testing.T) {
	if _, err := registry.ImageFromOCITar([]byte("not an OCI layout tar")); err == nil {
		t.Error("expected an error for bytes that are not an OCI layout tar")
	}
}

func TestLayerFromOCITar_RejectsTamperedLayer(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "original.txt", Mode: 0o644},
	}, map[string][]byte{"original.txt": []byte("original content")})
	imgTar, diffID := buildSingleLayerImageTar(t, layerTar)

	// The layout blob holds the layer's compressed bytes; its name is the
	// compressed digest, which stays in place while the content is swapped.
	origDigest, err := layerFromTar(t, layerTar).Digest()
	if err != nil {
		t.Fatalf("original layer digest: %v", err)
	}
	blobName := "blobs/" + origDigest.Algorithm + "/" + origDigest.Hex

	otherTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "other.txt", Mode: 0o644},
	}, map[string][]byte{"other.txt": []byte("different content entirely")})
	otherRC, err := layerFromTar(t, otherTar).Compressed()
	if err != nil {
		t.Fatalf("replacement layer: %v", err)
	}
	replacement, err := io.ReadAll(otherRC)
	if closeErr := otherRC.Close(); closeErr != nil {
		t.Fatalf("close replacement layer: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("read replacement layer: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tr := tar.NewReader(bytes.NewReader(imgTar))
	swapped := false
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read layout tar: %v", nextErr)
		}
		content, readErr := io.ReadAll(tr)
		if readErr != nil {
			t.Fatalf("read %s: %v", hdr.Name, readErr)
		}
		if hdr.Typeflag == tar.TypeReg && path.Clean(hdr.Name) == blobName {
			content = replacement
			swapped = true
		}
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(content))
		}
		if wErr := tw.WriteHeader(hdr); wErr != nil {
			t.Fatalf("write %s: %v", hdr.Name, wErr)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, wErr := tw.Write(content); wErr != nil {
				t.Fatalf("write %s content: %v", hdr.Name, wErr)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tampered tar: %v", err)
	}
	if !swapped {
		t.Fatalf("layer blob %s not found in layout tar", blobName)
	}

	// index.json, manifest, and config are untouched: the config still
	// declares the original diff_id, so selection succeeds and only the
	// content check can catch the swap.
	if _, err := registry.SeedTarFromImage(buf.Bytes(), diffID, "", ""); err == nil {
		t.Error("expected an error for a layer whose content does not hash to the requested diff_id")
	}
}
