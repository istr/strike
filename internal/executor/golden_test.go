package executor_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
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

var update = flag.Bool("update", false, "update golden files")

// goldenPath returns the path to a golden file in testdata/golden/.
func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", "golden", name)
}

// assertGolden compares got against a golden file. When -update is set,
// it writes got as the new golden value instead.
//
// This is the foundation for cross-validation: the golden files define
// the expected output that any implementation (Go, Rust) must produce
// for the same inputs.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenPath(t, name)

	if *update {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("update golden file %s: %v", name, err)
		}
		t.Logf("updated golden file: %s", path)
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatalf("read golden file %s: %v\n  run with -update to generate", name, err)
	}
	if string(got) != string(want) {
		t.Errorf("golden mismatch: %s\n  got:  %s\n  want: %s\n  run with -update to regenerate",
			name, got, want)
	}
}

// --------------------------------------------------------------------------.
// Deterministic test key
// --------------------------------------------------------------------------.

// testKey returns a deterministic ECDSA P-256 private key for golden tests.
// The key is derived from a fixed scalar, NOT from crypto/rand. This means
// SignManifest (which uses RFC 6979 deterministic nonces since Go 1.20)
// produces identical signatures across runs, platforms, and Go versions.
//
// NEVER use this key for anything other than tests.
func testKey(t *testing.T) (pemBytes []byte) {
	t.Helper()

	// Fixed scalar for deterministic key generation.
	// This is a valid P-256 private key scalar (32 bytes, < curve order).
	scalar, err := hex.DecodeString("c6ef4a1b3e84f72d9b0c5a8e7f123456789abcdef0123456789abcdef0123456")
	if err != nil {
		t.Fatalf("decode scalar: %v", err)
	}

	ecdhKey, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}

	// Convert ecdh key to ecdsa key via PKCS8 round-trip.
	ecdhDER, err := x509.MarshalPKCS8PrivateKey(ecdhKey)
	if err != nil {
		t.Fatalf("marshal ecdh key: %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(ecdhDER)
	if err != nil {
		t.Fatalf("parse ecdh key: %v", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("expected *ecdsa.PrivateKey")
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

// --------------------------------------------------------------------------.
// Golden test: SignManifest
// --------------------------------------------------------------------------.

// signGoldenResult is the JSON structure stored in golden files for signing.
// It captures the payload and key so a Rust verifier can reproduce the
// exact computation. The signature itself is verified cryptographically
// rather than by byte comparison because Go's ecdsa.Sign uses hedged
// nonces (RFC 6979 + crypto/rand), producing valid but non-deterministic
// signatures.
type signGoldenResult struct {
	ManifestDigest string `json:"manifest_digest"`
	Payload        string `json:"payload"` // simple signing JSON
	KeyPEM         string `json:"key_pem"` // the test key used
}

func TestSignManifest_Golden(t *testing.T) {
	keyPEM := testKey(t)

	// Fixed digest -- the input to signing.
	digest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	sigImage, err := executor.SignManifest(digest, keyPEM, nil)
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

	// Verify signature cryptographically instead of comparing bytes.
	// Go's ecdsa.Sign uses hedged nonces (RFC 6979 XORed with
	// crypto/rand), so signatures are valid but non-deterministic.
	verifySigP256(t, keyPEM, payload, sig)

	// Golden-test the deterministic parts: payload and key.
	result := signGoldenResult{
		ManifestDigest: digest,
		Payload:        string(payload),
		KeyPEM:         string(keyPEM),
	}

	got, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	assertGolden(t, "sign_manifest.json", got)
}

// verifySigP256 verifies a base64-encoded raw (r||s) ECDSA P-256 signature
// against the given payload using the public key from keyPEM.
func verifySigP256(t *testing.T, keyPEM, payload []byte, b64sig string) {
	t.Helper()

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("no PEM block in test key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("test key is not ECDSA")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	hash := sha256.Sum256(payload)

	if !ecdsa.Verify(&priv.PublicKey, hash[:], r, s) {
		t.Error("signature verification failed")
	}
}

// --------------------------------------------------------------------------.
// Golden test: AssembleImage
// --------------------------------------------------------------------------.

// assembleGoldenResult captures the deterministic outputs of image assembly.
type assembleGoldenResult struct {
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
	LayerCount     int    `json:"layer_count"`
}

func TestAssembleImage_Golden(t *testing.T) {
	// Create a minimal file to add as a layer
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "hello")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil { //nolint:gosec // G306: test binary must be executable
		t.Fatal(err)
	}

	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: "build.binary", Dest: "/usr/bin/hello", Mode: 0o755},
		},
		Config: &lane.ImageConfig{
			Entrypoint: []string{"/usr/bin/hello"},
			User:       "65534:65534",
		},
		Annotations: map[string]string{
			"org.opencontainers.image.source": "https://github.com/istr/strike",
		},
	}

	inputPaths := map[string]string{
		"build.binary": binPath,
	}

	// Use empty.Image as base — deterministic, no network
	result, err := executor.AssembleImage(empty.Image, spec, inputPaths)
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

	// Verify config was applied
	if cfg.Config.User != "65534:65534" {
		t.Errorf("user = %q, want 65534:65534", cfg.Config.User)
	}

	golden := assembleGoldenResult{
		ManifestDigest: result.Digest.String(),
		ConfigDigest:   cfgDigest.String(),
		LayerCount:     len(layers),
	}

	got, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	assertGolden(t, "assemble_image.json", got)
}

// --------------------------------------------------------------------------.
// Golden test: spec hash computation
// --------------------------------------------------------------------------.

func TestSpecHash_Golden(t *testing.T) {
	step := &lane.Step{
		Args: []string{"go", "build", "-o", "/out/binary", "./cmd/strike"},
		Env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux"},
	}
	imageDigest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	inputHashes := map[string]string{
		"src": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	sourceHashes := map[string]string{
		"go.sum": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	key := registry.SpecHash(step, imageDigest, inputHashes, sourceHashes)
	assertGolden(t, "spec_hash.txt", []byte(key))
}

// --------------------------------------------------------------------------.
// Helpers
// --------------------------------------------------------------------------.

// TestAssembleImage_Deterministic verifies that two identical assemblies
// produce the same manifest digest — the fundamental reproducibility
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

	// Assemble twice with identical inputs
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
// digest with a different base — catching accidental base-image independence.
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

	// Assembly with empty base
	r1, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	// Assembly with a base that has a label (different config)
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
