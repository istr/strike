package executor_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

var update = flag.Bool("update", false, "update cross-validation vector expected fields")

// --------------------------------------------------------------------------.
// Golden test: AssembleImage (crossval vector).
// --------------------------------------------------------------------------.

func TestAssembleImage_Golden(t *testing.T) {
	vec := loadVector[assembleVector](t, "assemble", "empty_base_single_file.json")

	if vec.Inputs.Base != "oci:empty" {
		t.Fatalf("unsupported base type: %q", vec.Inputs.Base)
	}

	// Decode file content from vector and write to temp dir.
	tmp := t.TempDir()
	inputPaths := make(map[string]string)
	for ref, f := range vec.Inputs.Files {
		content := decodeBase64(t, f.ContentBase64)
		hostPath := filepath.Join(tmp, filepath.Base(ref))
		if err := os.WriteFile(hostPath, content, fs.FileMode(f.Mode)); err != nil { //nolint:gosec // G306: test binary must be executable
			t.Fatalf("write test file %s: %v", ref, err)
		}
		inputPaths[ref] = hostPath
	}

	// Unmarshal spec from the vector.
	var spec lane.PackSpec
	if err := json.Unmarshal(vec.Inputs.Spec, &spec); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}

	result, err := executor.AssembleImage(empty.Image, &spec, inputPaths)
	if err != nil {
		t.Fatalf("AssembleImage: %v", err)
	}

	layers, err := result.Image.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}

	cfg, err := result.Image.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfgDigest, err := result.Image.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}

	// Verify config was applied.
	if cfg.Config.User != "65534:65534" {
		t.Errorf("user = %q, want 65534:65534", cfg.Config.User)
	}

	got := struct {
		ManifestDigest string `json:"manifest_digest"`
		ConfigDigest   string `json:"config_digest"`
		LayerCount     int    `json:"layer_count"`
	}{
		ManifestDigest: result.Digest.String(),
		ConfigDigest:   cfgDigest.String(),
		LayerCount:     len(layers),
	}

	if *update {
		updateVectorExpected(t, "assemble", "empty_base_single_file.json", got)
		return
	}

	if got.ManifestDigest != vec.Expected.ManifestDigest {
		t.Errorf("manifest_digest mismatch:\n  got:  %s\n  want: %s", got.ManifestDigest, vec.Expected.ManifestDigest)
	}
	if got.ConfigDigest != vec.Expected.ConfigDigest {
		t.Errorf("config_digest mismatch:\n  got:  %s\n  want: %s", got.ConfigDigest, vec.Expected.ConfigDigest)
	}
	if got.LayerCount != vec.Expected.LayerCount {
		t.Errorf("layer_count mismatch: got %d, want %d", got.LayerCount, vec.Expected.LayerCount)
	}
}

// --------------------------------------------------------------------------.
// Golden test: SpecHash (crossval vectors).
// --------------------------------------------------------------------------.

func TestSpecHash_Golden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(crossvalDir, "spechash", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no spechash vectors found")
	}

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			vec := loadVector[specHashVector](t, "spechash", name)

			step := &lane.Step{
				Args: vec.Inputs.Step.Args,
				Env:  vec.Inputs.Step.Env,
			}

			got := registry.SpecHash(step, vec.Inputs.ImageDigest, vec.Inputs.InputHashes, vec.Inputs.SourceHashes)

			if *update {
				updateVectorExpected(t, "spechash", name, struct {
					Hash string `json:"hash"`
				}{Hash: got})
				return
			}

			if got != vec.Expected.Hash {
				t.Errorf("hash mismatch:\n  got:  %s\n  want: %s", got, vec.Expected.Hash)
			}
		})
	}
}

// --------------------------------------------------------------------------.
// Golden test: SignManifest (crossval vector).
// --------------------------------------------------------------------------.

func TestSignManifest_Golden(t *testing.T) {
	vec := loadVector[signVector](t, "sign", "ecdsa_p256_pkcs8.json")

	keyPEM := []byte(vec.Inputs.KeyPEM)
	var password []byte
	if vec.Inputs.Password != nil {
		password = []byte(*vec.Inputs.Password)
	}

	sigImage, err := executor.SignManifest(vec.Inputs.ManifestDigest, keyPEM, password)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	// Extract signature from the OCI image annotations.
	manifest, err := sigImage.Manifest()
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	sig := manifest.Annotations["dev.sigstore.cosign/signature"]
	if sig == "" {
		t.Fatal("no signature annotation")
	}

	// Extract payload from the single layer.
	layers, err := sigImage.Layers()
	if err != nil || len(layers) == 0 {
		t.Fatal("no signature layers")
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatalf("uncompress layer: %v", err)
	}
	payload, err := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		t.Fatalf("close layer reader: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}

	// Verify signature cryptographically using the public key from the vector.
	verifySigP256DER(t, vec.Expected.Verify.PublicKeyDERBase64, payload, sig)

	if *update {
		updateVectorExpected(t, "sign", "ecdsa_p256_pkcs8.json", struct {
			Payload string `json:"payload"`
			Verify  struct {
				Algorithm          string `json:"algorithm"`
				PublicKeyDERBase64 string `json:"public_key_der_base64"`
			} `json:"verify"`
		}{
			Payload: string(payload),
			Verify: struct {
				Algorithm          string `json:"algorithm"`
				PublicKeyDERBase64 string `json:"public_key_der_base64"`
			}{
				Algorithm:          "ECDSA-P256-SHA256",
				PublicKeyDERBase64: vec.Expected.Verify.PublicKeyDERBase64,
			},
		})
		return
	}

	if string(payload) != vec.Expected.Payload {
		t.Errorf("payload mismatch:\n  got:  %s\n  want: %s", payload, vec.Expected.Payload)
	}
}

// verifySigP256DER verifies a base64-encoded raw (r||s) ECDSA P-256 signature
// against the given payload using a DER-encoded public key (base64).
func verifySigP256DER(t *testing.T, pubKeyDERBase64 string, payload []byte, b64sig string) {
	t.Helper()

	pubDER := decodeBase64(t, pubKeyDERBase64)
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not ECDSA")
	}

	sigBytes := decodeBase64(t, b64sig)
	if len(sigBytes) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	hash := sha256.Sum256(payload)

	if !ecdsa.Verify(ecPub, hash[:], r, s) {
		t.Error("signature verification failed")
	}
}

// --------------------------------------------------------------------------.
// Non-golden tests (kept as-is, no vector files needed).
// --------------------------------------------------------------------------.

// TestAssembleImage_Deterministic verifies that two identical assemblies
// produce the same manifest digest -- the fundamental reproducibility
// property that cross-validation depends on.
func TestAssembleImage_Deterministic(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "app")
	if err := os.WriteFile(binPath, []byte("binary-content"), 0o755); err != nil { //nolint:gosec // G306: test binary must be executable
		t.Fatal(err)
	}

	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: "step.out", Dest: "/app", Mode: 0o755},
		},
	}
	inputs := map[string]string{"step.out": binPath}

	r1, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	if r1.Digest != r2.Digest {
		t.Errorf("non-deterministic assembly:\n  run 1: %s\n  run 2: %s", r1.Digest, r2.Digest)
	}
}

// TestAssembleImage_WithMutatedBase verifies assembly produces a DIFFERENT
// digest with a different base -- catching accidental base-image independence.
func TestAssembleImage_WithMutatedBase(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "app")
	if err := os.WriteFile(binPath, []byte("binary"), 0o755); err != nil { //nolint:gosec // G306: test binary must be executable
		t.Fatal(err)
	}

	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: "step.out", Dest: "/app", Mode: 0o755},
		},
	}
	inputs := map[string]string{"step.out": binPath}

	r1, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	altBase, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{Labels: map[string]string{"base": "alt"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := executor.AssembleImage(altBase, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	if r1.Digest == r2.Digest {
		t.Error("different bases should produce different digests")
	}
}
