package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/istr/strike/internal/bundle"
)

// DSSE checks the bundle's DSSE signature over the in-toto statement
// with the leaf's public key and returns the statement payload. It enforces
// the in-toto payload type (the cross-protocol-confusion guard) and verifies
// the ASN.1-DER ECDSA P-256 signature over sha256 of the DSSE
// pre-authentication encoding -- the same PAE the producer signed.
func DSSE(pb *ParsedBundle, leaf *x509.Certificate) ([]byte, error) {
	env := pb.Envelope
	if env.GetPayloadType() != bundle.PayloadType {
		return nil, fmt.Errorf("%w: got %q", ErrPayloadType, env.GetPayloadType())
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: leaf key is %T, not ECDSA", ErrSignature, leaf.PublicKey)
	}
	pae := bundle.PAEEncode(env.GetPayloadType(), env.GetPayload())
	digest := sha256.Sum256(pae)
	if !ecdsa.VerifyASN1(pub, digest[:], env.GetSignatures()[0].GetSig()) {
		return nil, ErrSignature
	}
	return env.GetPayload(), nil
}
