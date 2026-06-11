package verify

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/istr/strike/internal/clock"
)

// TrustedTime parses the RFC3161 timestamp, verifies its CMS signature against
// the TSA certificate from the trusted root, confirms it was taken over the
// DSSE signature bytes, and returns its time. This is the authoritative
// trusted time: it, not the wall clock, is the certificate-validity reference,
// so an at-the-time valid but long-expired leaf verifies and a never-valid one
// does not.
//
// strike's producer requests certless tokens (no CertReq), and digitorus does
// not verify a token that embeds no certificate. The TSA leaf from the trusted
// root is injected so the signer can be found and the signature verified, the
// same way sigstore's timestamp verification does it.
func TrustedTime(pb *ParsedBundle, tm *TrustedMaterial) (clock.Time, error) {
	ts, err := timestamp.ParseResponse(pb.RFC3161)
	if err != nil {
		return clock.Time{}, fmt.Errorf("%w: parse: %w", ErrTrustedTime, err)
	}
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return clock.Time{}, fmt.Errorf("%w: token: %w", ErrTrustedTime, err)
	}
	if p7.Certificates == nil && tm.tsaLeaf != nil {
		p7.Certificates = []*x509.Certificate{tm.tsaLeaf}
	}
	if err := p7.VerifyWithOpts(x509.VerifyOptions{
		Roots:         tm.tsaRoots,
		Intermediates: tm.tsaIntermediates,
		CurrentTime:   ts.Time,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return clock.Time{}, fmt.Errorf("%w: TSA chain: %w", ErrTrustedTime, err)
	}
	sig := pb.Envelope.GetSignatures()[0].GetSig()
	h := ts.HashAlgorithm.New()
	h.Write(sig)
	if !bytes.Equal(ts.HashedMessage, h.Sum(nil)) {
		return clock.Time{}, fmt.Errorf("%w: imprint does not cover the signature", ErrTrustedTime)
	}
	return ts.Time, nil
}
