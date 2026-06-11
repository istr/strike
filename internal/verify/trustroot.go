package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
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
		rekorKeys:           map[string]ed25519.PublicKey{},
	}
	if err := loadCAs(tr.GetCertificateAuthorities(), tm.fulcioRoots, tm.fulcioIntermediates); err != nil {
		return nil, fmt.Errorf("%w: fulcio: %w", ErrTrustedRoot, err)
	}
	if err := loadCAs(tr.GetTimestampAuthorities(), tm.tsaRoots, tm.tsaIntermediates); err != nil {
		return nil, fmt.Errorf("%w: tsa: %w", ErrTrustedRoot, err)
	}
	for _, tl := range tr.GetTlogs() {
		pub, err := x509.ParsePKIXPublicKey(tl.GetPublicKey().GetRawBytes())
		if err != nil {
			return nil, fmt.Errorf("%w: tlog key: %w", ErrTrustedRoot, err)
		}
		ed, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: tlog key is not Ed25519", ErrTrustedRoot)
		}
		tm.rekorKeys[hex.EncodeToString(tl.GetLogId().GetKeyId())] = ed
	}
	if len(tm.rekorKeys) == 0 {
		return nil, fmt.Errorf("%w: no transparency-log keys", ErrTrustedRoot)
	}
	return tm, nil
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
