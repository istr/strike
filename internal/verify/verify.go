// Package verify is the offline consumer of strike's keyless deploy
// attestation bundles -- the counterpart to internal/deploy's producer.
// deploy signs and submits; verify checks, contacting no network.
//
// A bundle is verified in independent, fail-closed layers: the strict shape
// of the sigstore v0.3 bundle, the DSSE signature over the in-toto statement,
// the Fulcio leaf certificate's chain and bound identity, an RFC3161 trusted
// timestamp, and Rekor v2 transparency-log inclusion. This file holds the
// shared types and sentinel errors; each layer lives in its own file. The
// transparency-log layer and the end-to-end entrypoint are added on top of
// this core.
package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"errors"

	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"

	"github.com/istr/strike/internal/clock"
)

// Sentinel errors. Every verification failure is or wraps one of these: a
// verifier that cannot say why it failed is not auditable.
var (
	ErrTrustedRoot = errors.New("verify: trusted root")
	ErrBundleShape = errors.New("verify: bundle shape")
	ErrPayloadType = errors.New("verify: unexpected DSSE payload type")
	ErrSignature   = errors.New("verify: DSSE signature")
	ErrLeafChain   = errors.New("verify: leaf certificate chain")
	ErrIdentity    = errors.New("verify: certificate identity")
	ErrSCT         = errors.New("verify: embedded signed certificate timestamp")
	ErrTrustedTime = errors.New("verify: trusted timestamp")
	ErrInclusion   = errors.New("verify: transparency-log inclusion")
)

// TrustedMaterial is the parsed, ready-to-use form of a sigstore TrustedRoot:
// the certificate pools and transparency-log keys the verifier checks
// against. Produced by ParseTrustedRoot; never mutated after.
type TrustedMaterial struct {
	fulcioRoots         *x509.CertPool
	fulcioIntermediates *x509.CertPool
	tsaRoots            *x509.CertPool
	tsaIntermediates    *x509.CertPool
	// tsaLeaf is the TSA signing certificate, injected into a certless RFC3161
	// token so its CMS signature can be verified against the trusted root.
	tsaLeaf *x509.Certificate
	// rekorKeys maps the hex-encoded non-truncated C2SP signed-note key ID to
	// the log's Ed25519 public key and the window the trusted root declares
	// for it. Consumed by the inclusion layer.
	rekorKeys map[string]rekorKey
	// ctKeys maps the hex-encoded RFC 6962 log ID -- sha256 over the DER
	// SubjectPublicKeyInfo, which is not the C2SP derivation used above -- to
	// the log's ECDSA P-256 key and its window. Consumed by the SCT layer.
	ctKeys map[string]ctKey
}

// rekorKey is a Rekor v2 transparency-log key with the validity window the
// trusted root declares for it.
type rekorKey struct {
	validFrom clock.Time
	validTo   clock.Time
	pub       ed25519.PublicKey
}

// ctKey is a certificate-transparency log key with the validity window the
// trusted root declares for it.
type ctKey struct {
	validFrom clock.Time
	validTo   clock.Time
	pub       *ecdsa.PublicKey
}

// withinWindow reports whether t falls inside [from, to]. A zero bound is one
// the trusted root omitted and constrains nothing; a bound it declared always
// constrains (ADR-053 D1).
func withinWindow(t, from, to clock.Time) bool {
	return (from.IsZero() || !t.Before(from)) && (to.IsZero() || !t.After(to))
}

// ParsedBundle is the strict-shape-validated content of a sigstore v0.3
// bundle: exactly one DSSE envelope (one signature), one leaf certificate,
// one transparency-log entry, one RFC3161 timestamp.
type ParsedBundle struct {
	Envelope *protodsse.Envelope
	LeafDER  []byte
	TLE      *protorekor.TransparencyLogEntry
	RFC3161  []byte
}

// Verifier checks keyless attestation bundles against a fixed trusted root and
// an expected signer identity. Construct once with New, then Verify many
// bundles. It holds no network client and contacts nothing.
type Verifier struct {
	tm       *TrustedMaterial
	identity string
	issuer   string
}

// New returns a Verifier bound to the parsed trusted material and the signer
// identity (SAN) and OIDC issuer every accepted bundle must carry.
func New(tm *TrustedMaterial, identity, issuer string) *Verifier {
	return &Verifier{tm: tm, identity: identity, issuer: issuer}
}

// Verify checks a sigstore v0.3 bundle end to end and returns the verified
// in-toto statement payload. The order is fail-closed and total: strict
// bundle shape, RFC3161 trusted time, Fulcio leaf chain and bound identity at
// that time, the certificate-transparency proof embedded in that leaf, the
// DSSE signature, and Rekor v2 transparency-log inclusion. A returned payload
// has passed every layer; any failure returns a layer sentinel and no payload.
func (v *Verifier) Verify(bundleJSON []byte) ([]byte, error) {
	pb, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	trustedTime, err := TrustedTime(pb, v.tm)
	if err != nil {
		return nil, err
	}
	leaf, ca, err := Leaf(pb.LeafDER, v.tm, trustedTime, v.identity, v.issuer)
	if err != nil {
		return nil, err
	}
	if err = SCT(leaf, ca, v.tm); err != nil {
		return nil, err
	}
	payload, err := DSSE(pb, leaf)
	if err != nil {
		return nil, err
	}
	if err := Inclusion(pb, v.tm, leaf, trustedTime); err != nil {
		return nil, err
	}
	return payload, nil
}
