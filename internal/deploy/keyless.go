package deploy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/bundle"
)

// signStatementKeyless signs one projected in-toto statement with an ephemeral
// key and returns the DSSE envelope plus the raw signature (the signature is
// also needed for the RFC3161 timestamp request).
//
// The signature is ASN.1 DER ECDSA, which is what sigstore verifiers expect
// (a raw r||s encoding would be rejected).
func signStatementKeyless(statementJSON []byte, key *ecdsa.PrivateKey) (*protodsse.Envelope, []byte, error) {
	if key == nil {
		return nil, nil, errors.New("keyless: signing key is required")
	}
	pae := bundle.PAEEncode(bundle.PayloadType, statementJSON)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("keyless: sign dsse: %w", err)
	}
	env := &protodsse.Envelope{
		PayloadType: bundle.PayloadType,
		Payload:     statementJSON,
		Signatures:  []*protodsse.Signature{{Sig: sig}},
	}
	return env, sig, nil
}

// assembleKeylessBundle builds a sigstore v0.3 bundle from a signed DSSE
// envelope, the Fulcio leaf certificate (DER), the Rekor v2 transparency-log
// entry, and the RFC3161 timestamp token, and marshals it to the
// *.sigstore.json wire shape.
//
// Under Rekor v2 the tlog entry carries no SET and integratedTime is 0; trusted
// time is the RFC3161 timestamp. The caller is responsible for supplying a tlog
// entry whose inclusion proof and a timestamp that verify against the consumer's
// trust root.
func assembleKeylessBundle(env *protodsse.Envelope, leafCertDER []byte, tle *protorekor.TransparencyLogEntry, rfc3161 []byte) ([]byte, error) {
	if env == nil || len(leafCertDER) == 0 || tle == nil || len(rfc3161) == 0 {
		return nil, errors.New("keyless: envelope, leaf cert, tlog entry, and timestamp are all required")
	}
	pb := &protobundle.Bundle{
		MediaType: bundle.MediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: leafCertDER},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{tle},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
					{SignedTimestamp: rfc3161},
				},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: env},
	}
	out, err := protojson.Marshal(pb)
	if err != nil {
		return nil, fmt.Errorf("keyless: marshal bundle: %w", err)
	}
	if err := ValidateBundleJSON(out); err != nil {
		return nil, fmt.Errorf("keyless: %w", err)
	}
	return out, nil
}
