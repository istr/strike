package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/istr/strike/internal/clock"
)

// oidSCTList is the RFC 6962 SignedCertificateTimestampList extension. Fulcio
// embeds the CT log's response under it when it issues the leaf, so the proof
// travels with the certificate and needs no network to check.
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

const (
	// tlsHashSHA256 and tlsSigECDSA are the only SignatureAndHashAlgorithm
	// codes strike accepts (RFC 5246 7.4.1.4.1). One curve, one hash
	// (ADR-008): another pair is rejected, never dispatched on.
	tlsHashSHA256 = 4
	tlsSigECDSA   = 3
	// sctVersionV1 and sctEntryPrecert are the RFC 6962 version and
	// LogEntryType of an embedded SCT: the log signed a precertificate, so the
	// verifier reconstructs one rather than hashing the leaf as issued.
	sctVersionV1    = 0
	sctEntryPrecert = 1
	// sctSigTypeCertificateTimestamp is the RFC 6962 SignatureType covering an
	// SCT, distinguishing it from a tree-head signature.
	sctSigTypeCertificateTimestamp = 0
)

// signedCertificateTimestamp is one decoded SCT: the log that issued it, the
// time it claims, the log-defined extensions that are covered by the
// signature, and the signature itself.
type signedCertificateTimestamp struct {
	logID      []byte
	extensions []byte
	signature  []byte
	timestamp  uint64
}

// SCT verifies the certificate-transparency proof embedded in the Fulcio leaf
// against the CT log key in the trusted root. It reconstructs the
// precertificate the log actually signed -- the leaf's TBSCertificate with the
// SCT extension removed, prefixed by the hash of the issuer's public key --
// and checks the log's ECDSA signature over it, per RFC 6962 3.2.
//
// Exactly one SCT is required. strike's bundle shape is strict everywhere else
// (one envelope, one signature, one log entry, one timestamp) and is strict
// here too: a list is not a threshold to be met but a shape to be matched.
//
// The SCT carries its own timestamp inside the signed structure, so forging it
// breaks the signature. That makes it the authenticated reference for the CT
// log key's validity window (ADR-053 D2), and no borrowed time is needed here.
func SCT(leaf, issuer *x509.Certificate, tm *TrustedMaterial) error {
	sct, err := embeddedSCT(leaf)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSCT, err)
	}
	logID := hex.EncodeToString(sct.logID)
	key, ok := tm.ctKeys[logID]
	if !ok {
		return fmt.Errorf("%w: no trusted CT log for log ID %s", ErrSCT, logID)
	}
	issued, err := milliTime(sct.timestamp)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSCT, err)
	}
	if !withinWindow(issued, key.validFrom, key.validTo) {
		return fmt.Errorf("%w: SCT issued outside the CT log key validity", ErrSCT)
	}
	precert, err := tbsWithoutSCT(leaf.RawTBSCertificate)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSCT, err)
	}
	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	input, err := sctSignedInput(sct, issuerKeyHash[:], precert)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSCT, err)
	}
	digest := sha256.Sum256(input)
	if !ecdsa.VerifyASN1(key.pub, digest[:], sct.signature) {
		return fmt.Errorf("%w: signature does not verify under log %s", ErrSCT, logID)
	}
	return nil
}

// milliTime converts an RFC 6962 millisecond timestamp to a Time. The bound
// check keeps the conversion total: a value that large is not a date.
func milliTime(ms uint64) (clock.Time, error) {
	if ms > math.MaxInt64 {
		return clock.Time{}, errors.New("SCT timestamp out of range")
	}
	msec := int64(ms)
	return clock.Unix(msec/1000, (msec%1000)*int64(clock.Millisecond)), nil
}

// embeddedSCT finds the SCT list extension on the leaf and decodes it.
func embeddedSCT(leaf *x509.Certificate) (signedCertificateTimestamp, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidSCTList) {
			return parseSCTList(ext.Value)
		}
	}
	return signedCertificateTimestamp{}, errors.New("leaf carries no SCT extension")
}

// parseSCTList decodes an SCT list extension value. X.509 parsing has already
// unwrapped the extnValue OCTET STRING; RFC 6962 3.3 wraps the TLS-encoded
// SignedCertificateTimestampList in a second DER OCTET STRING, so one further
// unwrap comes before the TLS framing starts.
func parseSCTList(extValue []byte) (signedCertificateTimestamp, error) {
	var none signedCertificateTimestamp
	outer := cryptobyte.String(extValue)
	var tlsBytes cryptobyte.String
	if !outer.ReadASN1(&tlsBytes, cryptobyteasn1.OCTET_STRING) || !outer.Empty() {
		return none, errors.New("SCT extension is not a DER OCTET STRING")
	}
	var list cryptobyte.String
	if !tlsBytes.ReadUint16LengthPrefixed(&list) || !tlsBytes.Empty() {
		return none, errors.New("malformed SCT list")
	}
	var item cryptobyte.String
	if !list.ReadUint16LengthPrefixed(&item) {
		return none, errors.New("malformed SCT entry")
	}
	if !list.Empty() {
		return none, errors.New("more than one SCT; want exactly one")
	}
	return parseSCT(item)
}

// parseSCT decodes one TLS-encoded SignedCertificateTimestamp.
func parseSCT(s cryptobyte.String) (signedCertificateTimestamp, error) {
	var none signedCertificateTimestamp
	var version, hashAlg, sigAlg uint8
	var sct signedCertificateTimestamp
	var exts, sig cryptobyte.String
	if !s.ReadUint8(&version) || version != sctVersionV1 {
		return none, errors.New("SCT is not version v1")
	}
	if !s.ReadBytes(&sct.logID, sha256.Size) ||
		!s.ReadUint64(&sct.timestamp) ||
		!s.ReadUint16LengthPrefixed(&exts) ||
		!s.ReadUint8(&hashAlg) ||
		!s.ReadUint8(&sigAlg) ||
		!s.ReadUint16LengthPrefixed(&sig) ||
		!s.Empty() {
		return none, errors.New("malformed SCT")
	}
	if hashAlg != tlsHashSHA256 || sigAlg != tlsSigECDSA {
		return none, fmt.Errorf("SCT uses hash %d and algorithm %d, want SHA-256 and ECDSA", hashAlg, sigAlg)
	}
	sct.extensions = exts
	sct.signature = sig
	return sct, nil
}

// sctSignedInput rebuilds the RFC 6962 3.2 digitally-signed structure the log
// signed for an embedded SCT. The log-defined extensions are carried verbatim:
// they are covered by the signature and are not empty in practice, so dropping
// them would compute a digest the log never signed.
func sctSignedInput(sct signedCertificateTimestamp, issuerKeyHash, precertTBS []byte) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(sctVersionV1)
	b.AddUint8(sctSigTypeCertificateTimestamp)
	b.AddUint64(sct.timestamp)
	b.AddUint16(sctEntryPrecert)
	b.AddBytes(issuerKeyHash)
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(precertTBS) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sct.extensions) })
	return b.Bytes()
}

// tbsWithoutSCT returns the leaf's TBSCertificate with the SCT list extension
// removed. Those are the bytes the log signed over the precertificate: the
// precertificate differs from the issued leaf only in carrying the poison
// extension where the leaf carries the SCT list, and RFC 6962 3.2 defines the
// verifier's reconstruction as removing the latter.
func tbsWithoutSCT(tbsDER []byte) ([]byte, error) {
	prefix, exts, err := splitTBS(tbsDER)
	if err != nil {
		return nil, err
	}
	kept, err := extensionsWithoutSCT(exts)
	if err != nil {
		return nil, err
	}
	extTag := cryptobyteasn1.Tag(3).ContextSpecific().Constructed()
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddBytes(prefix)
		tbs.AddASN1(extTag, func(w *cryptobyte.Builder) {
			w.AddASN1(cryptobyteasn1.SEQUENCE, func(e *cryptobyte.Builder) {
				e.AddBytes(kept)
			})
		})
	})
	return b.Bytes()
}

// splitTBS separates a TBSCertificate into the verbatim bytes of every field
// before the extensions and the contents of the extensions SEQUENCE. The
// extensions are [3] EXPLICIT and the last field, so everything ahead of them
// is copied without being parsed.
func splitTBS(tbsDER []byte) (prefix []byte, exts cryptobyte.String, err error) {
	input := cryptobyte.String(tbsDER)
	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cryptobyteasn1.SEQUENCE) || !input.Empty() {
		return nil, nil, errors.New("TBSCertificate is not a single SEQUENCE")
	}
	extTag := cryptobyteasn1.Tag(3).ContextSpecific().Constructed()
	var wrapper cryptobyte.String
	found := false
	for !tbs.Empty() {
		var elem cryptobyte.String
		var tag cryptobyteasn1.Tag
		if !tbs.ReadAnyASN1Element(&elem, &tag) {
			return nil, nil, errors.New("malformed TBSCertificate field")
		}
		if tag == extTag {
			wrapper, found = elem, true
			break
		}
		prefix = append(prefix, elem...)
	}
	if !found {
		return nil, nil, errors.New("TBSCertificate carries no extensions")
	}
	if !tbs.Empty() {
		return nil, nil, errors.New("trailing data after TBSCertificate extensions")
	}
	var inner cryptobyte.String
	if !wrapper.ReadASN1(&inner, extTag) || !wrapper.Empty() {
		return nil, nil, errors.New("malformed extensions wrapper")
	}
	if !inner.ReadASN1(&exts, cryptobyteasn1.SEQUENCE) || !inner.Empty() {
		return nil, nil, errors.New("malformed extensions SEQUENCE")
	}
	return prefix, exts, nil
}

// extensionsWithoutSCT returns the concatenated DER of every extension except
// the SCT list, which must appear exactly once.
func extensionsWithoutSCT(exts cryptobyte.String) ([]byte, error) {
	var kept []byte
	removed := 0
	for !exts.Empty() {
		var elem cryptobyte.String
		if !exts.ReadASN1Element(&elem, cryptobyteasn1.SEQUENCE) {
			return nil, errors.New("malformed certificate extension")
		}
		body := elem
		var fields cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !body.ReadASN1(&fields, cryptobyteasn1.SEQUENCE) || !fields.ReadASN1ObjectIdentifier(&oid) {
			return nil, errors.New("certificate extension carries no OID")
		}
		if oid.Equal(oidSCTList) {
			removed++
			continue
		}
		kept = append(kept, elem...)
	}
	if removed != 1 {
		return nil, fmt.Errorf("%d SCT list extensions, want exactly 1", removed)
	}
	return kept, nil
}
