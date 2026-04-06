package executor

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// SignPayload signs arbitrary data with an ECDSA P-256 key.
// Returns a base64-encoded raw (r||s) signature and the public key
// fingerprint (sha256:<hex> of the DER-encoded SubjectPublicKeyInfo).
//
// keyPEM is the PEM-encoded private key (PKCS#8, EC, or encrypted cosign).
// password is the key passphrase; nil for unencrypted keys.
func SignPayload(data, keyPEM, password []byte) (b64sig, keyID string, err error) {
	privKey, loadErr := loadCosignKey(keyPEM, password)
	if loadErr != nil {
		return "", "", fmt.Errorf("load key: %w", loadErr)
	}

	digest := sha256.Sum256(data)
	r, s, signErr := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if signErr != nil {
		return "", "", fmt.Errorf("ecdsa sign: %w", signErr)
	}

	// Zero-pad r and s to 32 bytes each for P-256.
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	// Compute key fingerprint from the public key's SPKI encoding.
	pubDER, marshalErr := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if marshalErr != nil {
		return "", "", fmt.Errorf("marshal public key: %w", marshalErr)
	}
	fingerprint := sha256.Sum256(pubDER)

	return base64.StdEncoding.EncodeToString(sig),
		"sha256:" + hex.EncodeToString(fingerprint[:]),
		nil
}

// SignManifest produces a cosign-compatible OCI signature artefact for
// the given manifest digest.
//
// manifestDigest is the "sha256:..." digest of the image manifest to sign.
// keyPEM is the PEM-encoded ECDSA private key (cosign or PKCS#8 format).
// password is the key passphrase; empty slice for unencrypted keys.
// rekor is an optional Rekor client; if non-nil, the signature is submitted
// to the transparency log and Rekor annotations are added to the image.
//
// Returns the signature as a go-containerregistry v1.Image ready to be
// appended to an OCI Image Index as a referrer.
func SignManifest(ctx context.Context, manifestDigest string, keyPEM, password []byte, rekor *RekorClient) (v1.Image, error) {
	// Construct cosign simple signing payload.
	payload, err := json.Marshal(simpleSigning{
		Critical: criticalSection{
			Identity: identitySection{DockerReference: ""},
			Image:    imageSection{DockerManifestDigest: manifestDigest},
			Type:     "cosign container image signature",
		},
		Optional: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	b64sig, _, err := SignPayload(payload, keyPEM, password)
	if err != nil {
		return nil, err
	}

	annotations := map[string]string{
		"dev.sigstore.cosign/signature": b64sig,
	}

	// Submit to Rekor transparency log if configured.
	if rekor != nil {
		rekorAnnotations, rekorErr := submitToRekor(ctx, rekor, manifestDigest, b64sig, keyPEM, password)
		if rekorErr != nil {
			return nil, rekorErr
		}
		for k, v := range rekorAnnotations {
			annotations[k] = v
		}
	}

	// Build OCI signature artefact.
	layer := static.NewLayer(payload,
		types.MediaType("application/vnd.dev.cosign.simplesigning.v1+json"))

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	annotated, ok := mutate.Annotations(img, annotations).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("unexpected type from mutate.Annotations")
	}
	img = annotated

	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, fmt.Errorf("append signature layer: %w", err)
	}

	// Parse manifest digest for the subject descriptor
	h, err := v1.NewHash(manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("parse manifest digest: %w", err)
	}
	withSubject, ok := mutate.Subject(img, v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    h,
	}).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("unexpected type from mutate.Subject")
	}
	img = withSubject

	return img, nil
}

// submitToRekor submits the signature to a Rekor transparency log.
// Returns Rekor annotations on success, nil on warning (fail open),
// or a hard error on SET verification failure.
func submitToRekor(ctx context.Context, client *RekorClient, manifestDigest, b64sig string, keyPEM, password []byte) (map[string]string, error) {
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return nil, fmt.Errorf("rekor: decode signature: %w", err)
	}

	pubPEM, err := derivePublicKeyPEM(keyPEM, password)
	if err != nil {
		return nil, fmt.Errorf("rekor: derive public key: %w", err)
	}

	hexDigest := strings.TrimPrefix(manifestDigest, "sha256:")
	entry, err := client.SubmitHashedRekord(ctx, hexDigest, sig, pubPEM)
	if err != nil {
		var w *RekorTransientError
		if errors.As(err, &w) {
			log.Printf("WARN   rekor: %v", err)
			return nil, nil
		}
		return nil, err
	}

	return entry.Annotations(), nil
}

// loadCosignKey parses an ECDSA private key from PEM format.
// Supports both:
//   - cosign encrypted keys (ENCRYPTED COSIGN PRIVATE KEY)
//   - unencrypted PKCS#8 keys (PRIVATE KEY)
func loadCosignKey(pemBytes, password []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "ENCRYPTED COSIGN PRIVATE KEY", "ENCRYPTED SIGSTORE PRIVATE KEY":
		return decryptCosignKey(block.Bytes, password)
	case "PRIVATE KEY":
		return parsePKCS8(block.Bytes)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type: %q", block.Type)
	}
}

func parsePKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, not ECDSA", key)
	}
	return ecKey, nil
}

// cosign encrypted key format.
type cosignEncryptedKey struct {
	Cipher     cosignCipher `json:"cipher"`
	Ciphertext string       `json:"ciphertext"`
	KDF        cosignKDF    `json:"kdf"`
}

type cosignKDF struct {
	Name   string         `json:"name"`
	Salt   string         `json:"salt"`
	Params cosignScryptKP `json:"params"`
}

type cosignScryptKP struct {
	N int `json:"N"`
	R int `json:"r"`
	P int `json:"p"`
}

type cosignCipher struct {
	Name  string `json:"name"`
	Nonce string `json:"nonce"` // base64
}

func decryptCosignKey(data, password []byte) (*ecdsa.PrivateKey, error) {
	var ek cosignEncryptedKey
	if err := json.Unmarshal(data, &ek); err != nil {
		return nil, fmt.Errorf("unmarshal cosign key: %w", err)
	}

	if ek.KDF.Name != "scrypt" {
		return nil, fmt.Errorf("unsupported KDF: %q", ek.KDF.Name)
	}
	if ek.Cipher.Name != "nacl/secretbox" {
		return nil, fmt.Errorf("unsupported cipher: %q", ek.Cipher.Name)
	}

	salt, err := base64.StdEncoding.DecodeString(ek.KDF.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(ek.Cipher.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes, got %d", len(nonce))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ek.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	// Derive key via scrypt
	derived, err := scrypt.Key(password, salt, ek.KDF.Params.N, ek.KDF.Params.R, ek.KDF.Params.P, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}

	var secretKey [32]byte
	copy(secretKey[:], derived)
	var nonceArr [24]byte
	copy(nonceArr[:], nonce)

	// Decrypt with NaCl secretbox
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonceArr, &secretKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed (wrong password?)")
	}

	return parsePKCS8(plaintext)
}

// Cosign simple signing payload types.
type simpleSigning struct {
	Optional interface{}     `json:"optional"`
	Critical criticalSection `json:"critical"`
}

type criticalSection struct {
	Identity identitySection `json:"identity"`
	Image    imageSection    `json:"image"`
	Type     string          `json:"type"`
}

type identitySection struct {
	DockerReference string `json:"docker-reference"`
}

type imageSection struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}
