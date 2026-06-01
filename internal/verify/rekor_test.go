package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/verify"
)

func rekorKeyPair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate rekor key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal rekor public: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

func signedEntry(t *testing.T, key *ecdsa.PrivateKey) *lane.RekorEntry {
	t.Helper()
	body := base64.StdEncoding.EncodeToString([]byte(`{"kind":"dsse"}`))
	entry := &lane.RekorEntry{
		Body:           body,
		LogID:          "abc",
		IntegratedTime: 1700000000,
		LogIndex:       42,
	}
	payload, err := json.Marshal(executor.SETPayload{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogID:          entry.LogID,
		LogIndex:       entry.LogIndex,
	})
	if err != nil {
		t.Fatalf("marshal SET payload: %v", err)
	}
	digest := sha256.Sum256(payload)
	set, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	entry.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(set)
	return entry
}

func TestRekor_SET_Valid(t *testing.T) {
	key, pubPEM := rekorKeyPair(t)
	entry := signedEntry(t, key)
	if err := verify.Rekor(entry, pubPEM); err != nil {
		t.Fatalf("Rekor: %v", err)
	}
}

func TestRekor_SET_Tampered(t *testing.T) {
	key, pubPEM := rekorKeyPair(t)
	entry := signedEntry(t, key)
	entry.LogIndex = 9999 // tamper after signing
	err := verify.Rekor(entry, pubPEM)
	if !errors.Is(err, verify.ErrSET) {
		t.Errorf("expected ErrSET, got %v", err)
	}
}

func TestRekor_SET_WrongKey(t *testing.T) {
	key, _ := rekorKeyPair(t)
	_, otherPubPEM := rekorKeyPair(t)
	entry := signedEntry(t, key)
	err := verify.Rekor(entry, otherPubPEM)
	if !errors.Is(err, verify.ErrSET) {
		t.Errorf("expected ErrSET, got %v", err)
	}
}

func TestRekor_SET_BadPEM(t *testing.T) {
	key, _ := rekorKeyPair(t)
	entry := signedEntry(t, key)
	err := verify.Rekor(entry, []byte("not a pem"))
	if err == nil {
		t.Error("expected error for malformed rekor public key PEM")
	}
}
