package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// NoteKeyID computes the Rekor v2 transparency-log key identity: the
// non-truncated C2SP signed-note key id, SHA-256 over the origin, a newline,
// the Ed25519 algorithm byte (0x01), and the raw public key (rekor-tiles
// pkg/note). It is NOT the SHA-256 of the PKIX DER, which is the natural but
// wrong guess. The producer stamps this value into the trust root it emits and
// the verifier binds a checkpoint origin to a trusted key with it, so a single
// implementation is load bearing.
func NoteKeyID(origin string, pub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(append([]byte(origin+"\n\x01"), pub...))
	return sum[:]
}

// ParseEd25519PKIX extracts an Ed25519 public key from PKIX/SPKI DER, the
// encoding both the exported log key and a trust root's transparency-log entry
// carry.
func ParseEd25519PKIX(der []byte) (ed25519.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519", pub)
	}
	return ed, nil
}
