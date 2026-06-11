package verify

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/istr/strike/internal/clock"
)

// Fulcio issuer extensions: v2 (1.8) wraps the value in a DER UTF8String;
// the original (1.1) carries the raw string. V2 is read first.
var (
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidFulcioIssuer   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

// Leaf parses the leaf, verifies its chain to the Fulcio roots in tm at
// the trusted time (never the wall clock -- the leaf is short-lived and
// already expired by verification time), and checks that it binds exactly the
// expected SAN identity and OIDC issuer. Returns the parsed leaf: its key
// verifies the DSSE signature.
func Leaf(leafDER []byte, tm *TrustedMaterial, trustedTime clock.Time, identity, issuer string) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrLeafChain, err)
	}
	if _, vErr := leaf.Verify(x509.VerifyOptions{
		Roots:         tm.fulcioRoots,
		Intermediates: tm.fulcioIntermediates,
		CurrentTime:   trustedTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); vErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrLeafChain, vErr)
	}
	if !matchesIdentity(leaf, identity) {
		return nil, fmt.Errorf("%w: SAN does not carry %q", ErrIdentity, identity)
	}
	gotIssuer, err := certIssuer(leaf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	if gotIssuer != issuer {
		return nil, fmt.Errorf("%w: issuer %q != %q", ErrIdentity, gotIssuer, issuer)
	}
	return leaf, nil
}

func matchesIdentity(leaf *x509.Certificate, identity string) bool {
	for _, e := range leaf.EmailAddresses {
		if e == identity {
			return true
		}
	}
	for _, u := range leaf.URIs {
		if u.String() == identity {
			return true
		}
	}
	return false
}

func certIssuer(leaf *x509.Certificate) (string, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV2) {
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err != nil {
				return "", fmt.Errorf("decode issuer-v2 extension: %w", err)
			}
			return s, nil
		}
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidFulcioIssuer) {
			return string(ext.Value), nil
		}
	}
	return "", errors.New("no Fulcio issuer extension")
}
