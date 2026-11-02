package verify

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// Fulcio issuer extensions: v2 (1.8) wraps the value in a DER UTF8String;
// the original (1.1) carries the raw string. V2 is read first.
var (
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidFulcioIssuer   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

// Fulcio source extensions a lane may pin (ADR-057 D2), each a DER string
// like the issuer-v2 extension.
var (
	oidRunnerEnvironment      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidSourceRepositoryURI    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRepositoryDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
	oidSourceRepositoryRef    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}
	oidBuildConfigURI         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}
)

// Leaf parses the leaf, verifies its chain to the Fulcio roots in tm at
// the trusted time (never the wall clock -- the leaf is short-lived and
// already expired by verification time), and checks that it binds exactly the
// expected SAN identity, OIDC issuer and extension pins (nil pins none).
// Returns the parsed leaf, whose key verifies the DSSE signature, and the
// certificate that issued it, whose SubjectPublicKeyInfo the SCT layer
// hashes into the precertificate it reconstructs. The issuer is taken from
// the chain just verified rather than looked up again, so both layers rest
// on one chain build.
func Leaf(leafDER []byte, tm *TrustedMaterial, trustedTime clock.Time, identity primitive.StringOrURI, issuer endpoint.Address, ext *lane.FulcioExtensions) (*x509.Certificate, *x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse: %w", ErrLeafChain, err)
	}
	chains, vErr := leaf.Verify(x509.VerifyOptions{
		Roots:         tm.fulcioRoots,
		Intermediates: tm.fulcioIntermediates,
		CurrentTime:   trustedTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if vErr != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrLeafChain, vErr)
	}
	if len(chains) == 0 || len(chains[0]) < 2 {
		return nil, nil, fmt.Errorf("%w: verified chain carries no issuer", ErrLeafChain)
	}
	if idErr := Identity(leaf, identity, issuer, ext); idErr != nil {
		return nil, nil, idErr
	}
	return leaf, chains[0][1], nil
}

// Identity checks that the leaf binds exactly the expected SAN identity and
// OIDC issuer, and carries every extension ext pins (nil pins none). Leaf
// applies it after the chain verifies; the keyless producer applies it to
// the certificate Fulcio issued, before the first signature (ADR-041
// decision 6 as amended by ADR-057 D2), so the producer refuses a mismatch
// by the same check the verifier makes.
func Identity(leaf *x509.Certificate, identity primitive.StringOrURI, issuer endpoint.Address, ext *lane.FulcioExtensions) error {
	if !matchesIdentity(leaf, identity) {
		return fmt.Errorf("%w: SAN does not carry %q", ErrIdentity, identity)
	}
	gotIssuer, err := certIssuer(leaf)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	if gotIssuer != issuer.URL() {
		return fmt.Errorf("%w: issuer %q != %q", ErrIdentity, gotIssuer, issuer.URL())
	}
	return matchExtensions(leaf, ext)
}

// extensionPin is one declared extension value: the name the lane uses, the
// value the certificate must carry verbatim, and the Fulcio OID.
type extensionPin struct {
	name string
	want string
	oid  asn1.ObjectIdentifier
}

// declaredPins lists the pins ext declares; an omitted field is not checked.
func declaredPins(ext *lane.FulcioExtensions) []extensionPin {
	var pins []extensionPin
	if ext.SourceRepositoryURI != nil {
		pins = append(pins, extensionPin{name: "sourceRepositoryURI", want: ext.SourceRepositoryURI.String(), oid: oidSourceRepositoryURI})
	}
	if ext.SourceRepositoryDigest != nil {
		pins = append(pins, extensionPin{name: "sourceRepositoryDigest", want: ext.SourceRepositoryDigest.String(), oid: oidSourceRepositoryDigest})
	}
	if ext.SourceRepositoryRef != nil {
		pins = append(pins, extensionPin{name: "sourceRepositoryRef", want: ext.SourceRepositoryRef.String(), oid: oidSourceRepositoryRef})
	}
	if ext.BuildConfigURI != nil {
		pins = append(pins, extensionPin{name: "buildConfigURI", want: ext.BuildConfigURI.String(), oid: oidBuildConfigURI})
	}
	if ext.RunnerEnvironment != nil {
		pins = append(pins, extensionPin{name: "runnerEnvironment", want: ext.RunnerEnvironment.String(), oid: oidRunnerEnvironment})
	}
	return pins
}

// matchExtensions checks every pin ext declares against the leaf: the
// extension is present and carries the declared value verbatim.
func matchExtensions(leaf *x509.Certificate, ext *lane.FulcioExtensions) error {
	if ext == nil {
		return nil
	}
	for _, p := range declaredPins(ext) {
		got, found, err := stringExtension(leaf, p.oid)
		if err != nil {
			return fmt.Errorf("%w: decode %s extension: %w", ErrIdentity, p.name, err)
		}
		if !found {
			return fmt.Errorf("%w: no %s extension", ErrIdentity, p.name)
		}
		if got != p.want {
			return fmt.Errorf("%w: %s %q != %q", ErrIdentity, p.name, got, p.want)
		}
	}
	return nil
}

func matchesIdentity(leaf *x509.Certificate, identity primitive.StringOrURI) bool {
	want := identity.String()
	for _, e := range leaf.EmailAddresses {
		if e == want {
			return true
		}
	}
	for _, u := range leaf.URIs {
		if u.String() == want {
			return true
		}
	}
	return false
}

// stringExtension decodes the DER string value of the leaf's extension with
// the given OID and reports whether the extension is present. The issuer-v2
// extension and every pinned source extension are read through it.
func stringExtension(leaf *x509.Certificate, oid asn1.ObjectIdentifier) (string, bool, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oid) {
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err != nil {
				return "", true, err
			}
			return s, true, nil
		}
	}
	return "", false, nil
}

func certIssuer(leaf *x509.Certificate) (string, error) {
	v2, found, err := stringExtension(leaf, oidFulcioIssuerV2)
	if err != nil {
		return "", fmt.Errorf("decode issuer-v2 extension: %w", err)
	}
	if found {
		return v2, nil
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidFulcioIssuer) {
			return string(ext.Value), nil
		}
	}
	return "", errors.New("no Fulcio issuer extension")
}
