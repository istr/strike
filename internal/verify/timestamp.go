package verify

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/digitorus/timestamp"

	"github.com/istr/strike/internal/clock"
)

// TrustedTime parses the RFC3161 timestamp, verifies its signing chain
// to the TSA roots in tm, confirms it was taken over the DSSE signature
// bytes, and returns its time. This is the authoritative trusted time: it,
// not the wall clock, is the certificate-validity reference, so an at-the-time
// valid but long-expired leaf verifies and a never-valid one does not.
func TrustedTime(pb *ParsedBundle, tm *TrustedMaterial) (clock.Time, error) {
	ts, err := timestamp.ParseResponse(pb.RFC3161)
	if err != nil {
		return clock.Time{}, fmt.Errorf("%w: parse: %w", ErrTrustedTime, err)
	}
	if len(ts.Certificates) == 0 {
		return clock.Time{}, fmt.Errorf("%w: no TSA certificate in token", ErrTrustedTime)
	}
	intermediates := tm.tsaIntermediates.Clone()
	for _, c := range ts.Certificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := ts.Certificates[0].Verify(x509.VerifyOptions{
		Roots:         tm.tsaRoots,
		Intermediates: intermediates,
		CurrentTime:   ts.Time,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return clock.Time{}, fmt.Errorf("%w: TSA chain: %w", ErrTrustedTime, err)
	}
	sig := pb.Envelope.GetSignatures()[0].GetSig()
	h := ts.HashAlgorithm.New()
	h.Write(sig)
	if !bytes.Equal(ts.HashedMessage, h.Sum(nil)) {
		return clock.Time{}, fmt.Errorf("%w: timestamp imprint does not cover the signature", ErrTrustedTime)
	}
	return ts.Time, nil
}
