package verify

import (
	"crypto/x509"

	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

// NewTestTrustedMaterial builds TrustedMaterial directly from parsed certs,
// for the self-contained layer tests, none of which reaches the inclusion
// layer. Production always goes through ParseTrustedRoot.
func NewTestTrustedMaterial(fulcioRoot, tsaRoot, tsaLeaf *x509.Certificate) *TrustedMaterial {
	fr := x509.NewCertPool()
	fr.AddCert(fulcioRoot)
	tr := x509.NewCertPool()
	tr.AddCert(tsaRoot)
	return &TrustedMaterial{
		fulcioRoots:         fr,
		fulcioIntermediates: x509.NewCertPool(),
		tsaRoots:            tr,
		tsaIntermediates:    x509.NewCertPool(),
		tsaLeaf:             tsaLeaf,
	}
}

// NewTestParsedBundle builds a ParsedBundle for the layer tests.
func NewTestParsedBundle(env *protodsse.Envelope, leafDER []byte, tle *protorekor.TransparencyLogEntry, rfc3161 []byte) *ParsedBundle {
	return &ParsedBundle{Envelope: env, LeafDER: leafDER, TLE: tle, RFC3161: rfc3161}
}
