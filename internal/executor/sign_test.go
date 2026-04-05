package executor_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/istr/strike/internal/executor"
)

// generateTestKey generates a fresh ECDSA P-256 key and returns the private
// key and its PKCS#8 PEM encoding.
func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// generateECKey returns a PEM with "EC PRIVATE KEY" type.
func generateECKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// encryptCosignKey encrypts a PKCS#8 DER key using the cosign format.
func encryptCosignKey(t *testing.T, key *ecdsa.PrivateKey, password string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, 32)
	if _, readErr := rand.Read(salt); readErr != nil {
		t.Fatal(readErr)
	}
	nonce := make([]byte, 24)
	if _, readErr := rand.Read(nonce); readErr != nil {
		t.Fatal(readErr)
	}

	// Use low scrypt params for test speed.
	derived, err := scrypt.Key([]byte(password), salt, 1024, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}

	var secretKey [32]byte
	copy(secretKey[:], derived)
	var nonceArr [24]byte
	copy(nonceArr[:], nonce)

	ciphertext := secretbox.Seal(nil, der, &nonceArr, &secretKey)

	envelope := map[string]any{
		"kdf": map[string]any{
			"name":   "scrypt",
			"salt":   base64.StdEncoding.EncodeToString(salt),
			"params": map[string]int{"N": 1024, "r": 8, "p": 1},
		},
		"cipher": map[string]any{
			"name":  "nacl/secretbox",
			"nonce": base64.StdEncoding.EncodeToString(nonce),
		},
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED COSIGN PRIVATE KEY",
		Bytes: body,
	})
}

// --------------------------------------------------------------------------.
// TestSignManifest with various key types.
// --------------------------------------------------------------------------.

func testDigest() string {
	h := sha256.Sum256([]byte("test-content"))
	return fmt.Sprintf("sha256:%x", h[:])
}

func TestSignManifest_PKCS8(t *testing.T) {
	key, pemBytes := generateTestKey(t)
	verifyRoundTrip(t, pemBytes, nil, &key.PublicKey)
}

func TestSignManifest_ECKey(t *testing.T) {
	key, pemBytes := generateECKey(t)
	verifyRoundTrip(t, pemBytes, nil, &key.PublicKey)
}

func TestSignManifest_EncryptedCosignKey(t *testing.T) {
	key, _ := generateTestKey(t)
	encrypted := encryptCosignKey(t, key, "test-password")
	verifyRoundTrip(t, encrypted, []byte("test-password"), &key.PublicKey)
}

func TestSignManifest_WrongPassword(t *testing.T) {
	key, _ := generateTestKey(t)
	encrypted := encryptCosignKey(t, key, "correct")
	_, err := executor.SignManifest(testDigest(), encrypted, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestSignManifest_EmptyPEM(t *testing.T) {
	_, err := executor.SignManifest(testDigest(), []byte("not a pem"), nil)
	if err == nil {
		t.Fatal("expected error for empty PEM")
	}
}

func TestSignManifest_UnsupportedPEMType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})
	_, err := executor.SignManifest(testDigest(), pemBytes, nil)
	if err == nil {
		t.Fatal("expected error for unsupported PEM type")
	}
}

// --------------------------------------------------------------------------.
// Round-trip signature verification.
// --------------------------------------------------------------------------.

// verifyRoundTrip signs a test digest and verifies the signature cryptographically.
func verifyRoundTrip(t *testing.T, keyPEM, password []byte, pub *ecdsa.PublicKey) {
	t.Helper()
	digest := testDigest()
	img, err := executor.SignManifest(digest, keyPEM, password)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	// Check image structure.
	layers, err := img.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}
	if len(layers) != 1 {
		t.Fatalf("layer count = %d, want 1", len(layers))
	}

	// Extract signature annotation.
	manifest, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	b64sig := manifest.Annotations["dev.sigstore.cosign/signature"]
	if b64sig == "" {
		t.Fatal("no signature annotation")
	}

	// Extract payload.
	payload := extractPayload(t, layers[0])

	// Verify ECDSA signature.
	sigBytes, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	hash := sha256.Sum256(payload)
	if !ecdsa.Verify(pub, hash[:], r, s) {
		t.Error("ECDSA signature verification failed")
	}
}

func extractPayload(t *testing.T, layer v1.Layer) []byte {
	t.Helper()
	rc, err := layer.Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
