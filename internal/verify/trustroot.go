package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/wire"
)

// ParseTrustedRoot parses a sigstore TrustedRoot JSON document into the pools
// and keys the verifier checks against. No network access; accepts the same
// trusted_root.json a production deployment supplies or the harness exports.
func ParseTrustedRoot(jsonBytes []byte) (*TrustedMaterial, error) {
	var tr trustrootpb.TrustedRoot
	if err := protojson.Unmarshal(jsonBytes, &tr); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %w", ErrTrustedRoot, err)
	}
	tm := &TrustedMaterial{
		fulcioRoots:         x509.NewCertPool(),
		fulcioIntermediates: x509.NewCertPool(),
		tsaRoots:            x509.NewCertPool(),
		tsaIntermediates:    x509.NewCertPool(),
		rekorKeys:           map[primitive.Sha256]rekorKey{},
		ctKeys:              map[primitive.Sha256]ctKey{},
	}
	if err := loadCAs(tr.GetCertificateAuthorities(), tm.fulcioRoots, tm.fulcioIntermediates); err != nil {
		return nil, fmt.Errorf("%w: fulcio: %w", ErrTrustedRoot, err)
	}
	if err := loadCAs(tr.GetTimestampAuthorities(), tm.tsaRoots, tm.tsaIntermediates); err != nil {
		return nil, fmt.Errorf("%w: tsa: %w", ErrTrustedRoot, err)
	}
	// Capture the TSA signing leaf (first cert of the first authority's chain,
	// leaf-first per the X509CertificateChain convention) for injection into
	// certless RFC3161 tokens. It is also present in the intermediate pool,
	// which is harmless for chain building.
	if tsas := tr.GetTimestampAuthorities(); len(tsas) > 0 {
		chain := tsas[0].GetCertChain().GetCertificates()
		if len(chain) > 0 {
			leaf, err := x509.ParseCertificate(chain[0].GetRawBytes())
			if err != nil {
				return nil, fmt.Errorf("%w: tsa leaf: %w", ErrTrustedRoot, err)
			}
			tm.tsaLeaf = leaf
		}
	}
	if err := loadLogKeys(tm, &tr); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTrustedRoot, err)
	}
	return tm, nil
}

// loadLogKeys fills rekorKeys and ctKeys from the trusted root's
// transparency-log and certificate-transparency log entries. Each key id must
// be sha256.Size bytes: both derivations, the C2SP signed-note key id and the
// RFC 6962 log id, are SHA-256 outputs, and an id of any other length names no
// key a bundle or an SCT can select. A root without a key of either kind is
// not usable material.
func loadLogKeys(tm *TrustedMaterial, tr *trustrootpb.TrustedRoot) error {
	for _, tl := range tr.GetTlogs() {
		edKey, err := wire.ParseEd25519PKIX(tl.GetPublicKey().GetRawBytes())
		if err != nil {
			return fmt.Errorf("tlog key: %w", err)
		}
		id := tl.GetLogId().GetKeyId()
		if len(id) != sha256.Size {
			return fmt.Errorf("tlog key id is %d bytes, want %d", len(id), sha256.Size)
		}
		from, to := keyWindow(tl)
		tm.rekorKeys[logKeyID(id)] = rekorKey{
			validFrom: from, validTo: to, pub: edKey,
		}
	}
	if len(tm.rekorKeys) == 0 {
		return errors.New("no transparency-log keys")
	}
	for _, cl := range tr.GetCtlogs() {
		ecKey, err := parseECDSAP256PKIX(cl.GetPublicKey().GetRawBytes())
		if err != nil {
			return fmt.Errorf("ctlog key: %w", err)
		}
		id := cl.GetLogId().GetKeyId()
		if len(id) != sha256.Size {
			return fmt.Errorf("ctlog key id is %d bytes, want %d", len(id), sha256.Size)
		}
		from, to := keyWindow(cl)
		tm.ctKeys[logKeyID(id)] = ctKey{
			validFrom: from, validTo: to, pub: ecKey,
		}
	}
	if len(tm.ctKeys) == 0 {
		return errors.New("no certificate-transparency log keys")
	}
	return nil
}

// logKeyID renders a transparency-log key id as the hex primitive that keys
// rekorKeys and ctKeys. Every caller holds an id of sha256.Size bytes: checked
// at the trusted root and at the bundle, fixed by the SCT encoding.
func logKeyID(id []byte) primitive.Sha256 {
	return primitive.Sha256(hex.EncodeToString(id))
}

// keyWindow reads the validity window a trusted-root log entry declares for
// its key. A bound the document omits stays the zero Time and constrains
// nothing. The nil checks are load bearing: protobuf maps an absent timestamp
// to the Unix epoch rather than to the zero Time, so an omitted end would
// otherwise read as 1970 and reject every bundle.
func keyWindow(tl *trustrootpb.TransparencyLogInstance) (from, to clock.Time) {
	vf := tl.GetPublicKey().GetValidFor()
	if s := vf.GetStart(); s != nil {
		from = s.AsTime()
	}
	if e := vf.GetEnd(); e != nil {
		to = e.AsTime()
	}
	return from, to
}

// parseECDSAP256PKIX extracts an ECDSA P-256 public key from PKIX/SPKI DER,
// the encoding a trusted root's certificate-transparency entry carries. One
// curve only (ADR-008): another curve is rejected, never dispatched on.
func parseECDSAP256PKIX(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ecdsa", pub)
	}
	if ec.Curve != elliptic.P256() {
		return nil, errors.New("public key is not on P-256")
	}
	return ec, nil
}

// loadCAs splits each authority's chain into the root pool (last cert) and
// the intermediate pool (earlier certs).
func loadCAs(cas []*trustrootpb.CertificateAuthority, roots, intermediates *x509.CertPool) error {
	for _, ca := range cas {
		chain := ca.GetCertChain().GetCertificates()
		if len(chain) == 0 {
			return errors.New("authority with empty chain")
		}
		for i, raw := range chain {
			cert, err := x509.ParseCertificate(raw.GetRawBytes())
			if err != nil {
				return fmt.Errorf("parse cert: %w", err)
			}
			if i == len(chain)-1 {
				roots.AddCert(cert)
			} else {
				intermediates.AddCert(cert)
			}
		}
	}
	return nil
}
