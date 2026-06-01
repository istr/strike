package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

// ErrSET is returned when the Rekor Signed Entry Timestamp does not verify
// against the supplied Rekor public key. A failed SET check is a hard
// failure: a forged transparency-log receipt is a security event.
var ErrSET = errors.New("verify: rekor SET verification failed")

// Rekor verifies a Rekor entry offline: the Signed Entry Timestamp against
// rekorPubPEM. It contacts no network: the entry is taken from the
// attestation, the public key from the caller.
//
// The SET is an ASN.1-DER ECDSA signature over sha256 of the canonical
// SETPayload (executor.SETPayload), matching the producer's submission-time
// verification. The payload type is reused, not redeclared, so the canonical
// field order stays single-sourced.
//
// Inclusion-proof verification is deferred to a follow-up (76b) once a real
// Rekor response fixture is available to pin the leaf preimage; the SET
// check is the security-load-bearing half and lands here.
func Rekor(entry *lane.RekorEntry, rekorPubPEM []byte) error {
	pub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		return fmt.Errorf("verify: parse rekor public key: %w", err)
	}
	return verifyRekorSET(entry, pub)
}

// verifyRekorSET reconstructs the canonical SET payload and checks the
// ASN.1-DER ECDSA signature carried in entry.SignedEntryTimestamp.
func verifyRekorSET(entry *lane.RekorEntry, pub *ecdsa.PublicKey) error {
	payload, err := json.Marshal(executor.SETPayload{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogID:          entry.LogID,
		LogIndex:       entry.LogIndex,
	})
	if err != nil {
		return fmt.Errorf("verify: canonicalize SET payload: %w", err)
	}
	set, err := base64.StdEncoding.DecodeString(entry.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("verify: decode SET: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], set) {
		return ErrSET
	}
	return nil
}
