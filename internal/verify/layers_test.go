package verify_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/digitorus/timestamp"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/verify"
)

const (
	testIdentity = "tester@strike.localhost"
	testIssuer   = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
)

var oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// signStatementInline mirrors the producer's signStatementKeyless using only
// exported symbols: PAE over the in-toto type, sha256, DER ECDSA. It builds a
// producer-shaped DSSE envelope so the verifier is exercised against the real
// wire shape without any production export.
func signStatementInline(t *testing.T, stmt []byte, key *ecdsa.PrivateKey) (*protodsse.Envelope, []byte) {
	t.Helper()
	pae := deploy.PAEEncode(deploy.InTotoPayloadType, stmt)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &protodsse.Envelope{
		PayloadType: deploy.InTotoPayloadType,
		Payload:     stmt,
		Signatures:  []*protodsse.Signature{{Sig: sig}},
	}, sig
}

// signedEnvelopeWithSig wraps an arbitrary signature in an in-toto DSSE
// envelope shape for the timestamp imprint test (the signature need not
// verify; the timestamp covers its bytes).
func signedEnvelopeWithSig(sig []byte) *protodsse.Envelope {
	return &protodsse.Envelope{
		PayloadType: deploy.InTotoPayloadType,
		Payload:     []byte("{}"),
		Signatures:  []*protodsse.Signature{{Sig: sig}},
	}
}

type testPKI struct {
	now        clock.Time
	fulcioRoot *x509.Certificate
	leaf       *x509.Certificate
	leafKey    *ecdsa.PrivateKey
	tsaRoot    *x509.Certificate
	tsaLeaf    *x509.Certificate
	tsaKey     *ecdsa.PrivateKey
	rekorPub   ed25519.PublicKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	// The reference instant for all validity windows. It must track the wall
	// clock: digitorus's CreateResponse embeds the wall-clock signing time in
	// the PKCS7 token and ParseResponse rejects a token whose signing time is
	// outside the TSA certificate window. Truncated to whole seconds because
	// RFC3161 GeneralizedTime carries no sub-second precision.
	now := clock.Wall().UTC().Truncate(clock.Second)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio"},
		NotBefore:             now.Add(-clock.Hour),
		NotAfter:              now.Add(24 * clock.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	fulcioRoot := selfSign(t, caTmpl, caKey)

	issuerExt, err := asn1.MarshalWithParams(testIssuer, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		NotBefore:       now.Add(-clock.Minute),
		NotAfter:        now.Add(10 * clock.Minute),
		EmailAddresses:  []string{testIdentity},
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: oidIssuerV2, Value: issuerExt}},
	}
	leaf := signCert(t, leafTmpl, &leafKey.PublicKey, caTmpl, caKey)

	tsaCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tsaCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "test-tsa-ca"},
		NotBefore:             now.Add(-clock.Hour),
		NotAfter:              now.Add(24 * clock.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	tsaRoot := selfSign(t, tsaCATmpl, tsaCAKey)
	tsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		NotBefore:    now.Add(-clock.Minute),
		NotAfter:     now.Add(clock.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	tsaLeaf := signCert(t, tsaTmpl, &tsaKey.PublicKey, tsaCATmpl, tsaCAKey)

	rekorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{
		now:        now,
		fulcioRoot: fulcioRoot,
		leaf:       leaf,
		leafKey:    leafKey,
		tsaRoot:    tsaRoot,
		tsaLeaf:    tsaLeaf,
		tsaKey:     tsaKey,
		rekorPub:   rekorPub,
	}
}

func selfSign(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func signCert(t *testing.T, tmpl *x509.Certificate, pub any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func (p *testPKI) material(t *testing.T) *verify.TrustedMaterial {
	t.Helper()
	rekorDER, err := x509.MarshalPKIXPublicKey(p.rekorPub)
	if err != nil {
		t.Fatal(err)
	}
	logID := sha256.Sum256(rekorDER) // arbitrary stable ID for the test map
	return verify.NewTestTrustedMaterial(p.fulcioRoot, p.tsaRoot, string(logID[:]), p.rekorPub)
}

// trustedRootJSON round-trips the test material through the production
// ParseTrustedRoot, exercising E2.
func (p *testPKI) trustedRootJSON(t *testing.T) []byte {
	t.Helper()
	rekorDER, err := x509.MarshalPKIXPublicKey(p.rekorPub)
	if err != nil {
		t.Fatal(err)
	}
	tr := &trustrootpb.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		CertificateAuthorities: []*trustrootpb.CertificateAuthority{
			{CertChain: &commonpb.X509CertificateChain{
				Certificates: []*commonpb.X509Certificate{{RawBytes: p.fulcioRoot.Raw}},
			}},
		},
		TimestampAuthorities: []*trustrootpb.CertificateAuthority{
			{CertChain: &commonpb.X509CertificateChain{
				Certificates: []*commonpb.X509Certificate{{RawBytes: p.tsaRoot.Raw}},
			}},
		},
		Tlogs: []*trustrootpb.TransparencyLogInstance{
			{
				PublicKey: &commonpb.PublicKey{RawBytes: rekorDER},
				LogId:     &commonpb.LogId{KeyId: []byte("test-log-id")},
			},
		},
	}
	out, err := protojson.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseTrustedRoot(t *testing.T) {
	p := newTestPKI(t)
	if _, err := verify.ParseTrustedRoot(p.trustedRootJSON(t)); err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
	}

	// Garbage JSON and a document without transparency-log keys must fail
	// closed with ErrTrustedRoot.
	if _, err := verify.ParseTrustedRoot([]byte("{")); !errors.Is(err, verify.ErrTrustedRoot) {
		t.Fatalf("garbage JSON: got %v, want ErrTrustedRoot", err)
	}
	if _, err := verify.ParseTrustedRoot([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`)); !errors.Is(err, verify.ErrTrustedRoot) {
		t.Fatalf("no tlog keys: got %v, want ErrTrustedRoot", err)
	}
}

// validBundle marshals a well-formed v0.3 bundle, optionally mutated first.
func validBundle(t *testing.T, mutate func(*protobundle.Bundle)) []byte {
	t.Helper()
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &commonpb.X509Certificate{RawBytes: []byte("leaf-der")},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{{LogIndex: 7}},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*commonpb.RFC3161SignedTimestamp{
					{SignedTimestamp: []byte("token")},
				},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: signedEnvelopeWithSig([]byte("sig"))},
	}
	if mutate != nil {
		mutate(pb)
	}
	out, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseBundle(t *testing.T) {
	pb, err := verify.ParseBundle(validBundle(t, nil))
	if err != nil {
		t.Fatalf("ParseBundle (happy): %v", err)
	}
	if string(pb.LeafDER) != "leaf-der" || string(pb.RFC3161) != "token" || pb.TLE.GetLogIndex() != 7 {
		t.Fatalf("ParseBundle extracted wrong content: %+v", pb)
	}
	if pb.Envelope.GetPayloadType() != deploy.InTotoPayloadType {
		t.Fatalf("envelope payload type = %q", pb.Envelope.GetPayloadType())
	}

	tests := []struct {
		name   string
		bundle []byte
	}{
		{"not json", []byte("{")},
		{"wrong media type", validBundle(t, func(b *protobundle.Bundle) {
			b.MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.2"
		})},
		{"no dsse envelope", validBundle(t, func(b *protobundle.Bundle) {
			b.Content = nil
		})},
		{"zero signatures", validBundle(t, func(b *protobundle.Bundle) {
			b.GetDsseEnvelope().Signatures = nil
		})},
		{"two signatures", validBundle(t, func(b *protobundle.Bundle) {
			env := b.GetDsseEnvelope()
			env.Signatures = append(env.Signatures, env.Signatures[0])
		})},
		{"no verification material", validBundle(t, func(b *protobundle.Bundle) {
			b.VerificationMaterial = nil
		})},
		{"no leaf certificate", validBundle(t, func(b *protobundle.Bundle) {
			b.VerificationMaterial.Content = nil
		})},
		{"two tlog entries", validBundle(t, func(b *protobundle.Bundle) {
			vm := b.VerificationMaterial
			vm.TlogEntries = append(vm.TlogEntries, vm.TlogEntries[0])
		})},
		{"no rfc3161 timestamp", validBundle(t, func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData = nil
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := verify.ParseBundle(tt.bundle); !errors.Is(err, verify.ErrBundleShape) {
				t.Fatalf("got %v, want ErrBundleShape", err)
			}
		})
	}
}

func TestLeafAndDSSE(t *testing.T) {
	p := newTestPKI(t)
	tm := p.material(t)

	leaf, err := verify.Leaf(p.leaf.Raw, tm, p.now, testIdentity, testIssuer)
	if err != nil {
		t.Fatalf("Leaf (happy): %v", err)
	}

	// Wrong identity and wrong issuer must fail.
	if _, gotErr := verify.Leaf(p.leaf.Raw, tm, p.now, "attacker@evil", testIssuer); !errors.Is(gotErr, verify.ErrIdentity) {
		t.Fatalf("wrong identity: got %v, want ErrIdentity", gotErr)
	}
	if _, gotErr := verify.Leaf(p.leaf.Raw, tm, p.now, testIdentity, "https://evil"); !errors.Is(gotErr, verify.ErrIdentity) {
		t.Fatalf("wrong issuer: got %v, want ErrIdentity", gotErr)
	}
	// Outside validity must fail on the chain.
	if _, gotErr := verify.Leaf(p.leaf.Raw, tm, p.now.Add(clock.Hour), testIdentity, testIssuer); !errors.Is(gotErr, verify.ErrLeafChain) {
		t.Fatalf("expired: got %v, want ErrLeafChain", gotErr)
	}

	// DSSE: sign a statement with the leaf key, wrap as a ParsedBundle.
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)
	env, _ := signStatementInline(t, stmt, p.leafKey)
	pb := verify.NewTestParsedBundle(env, p.leaf.Raw, nil, nil)
	payload, err := verify.DSSE(pb, leaf)
	if err != nil {
		t.Fatalf("DSSE: %v", err)
	}
	if string(payload) != string(stmt) {
		t.Fatalf("payload mismatch")
	}
	// Tampered payload must fail.
	env.Payload = append(env.GetPayload(), '!')
	if _, err := verify.DSSE(verify.NewTestParsedBundle(env, p.leaf.Raw, nil, nil), leaf); !errors.Is(err, verify.ErrSignature) {
		t.Fatalf("tampered payload: got %v, want ErrSignature", err)
	}
}

func TestTrustedTime(t *testing.T) {
	p := newTestPKI(t)
	tm := p.material(t)

	sig := []byte("dsse-signature-bytes")
	h := sha256.Sum256(sig)
	tsReq := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     h[:],
		Time:              p.now,
		AddTSACertificate: true, // embed the signing cert; verifier fail-closes without it
		// CreateResponse marshals the policy OID unconditionally; a nil
		// policy is an invalid OID. The value itself is not verified.
		Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
	}
	token, err := tsReq.CreateResponseWithOpts(p.tsaLeaf, p.tsaKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}

	env := signedEnvelopeWithSig(sig)
	pb := verify.NewTestParsedBundle(env, p.leaf.Raw, nil, token)
	got, err := verify.TrustedTime(pb, tm)
	if err != nil {
		t.Fatalf("TrustedTime: %v", err)
	}
	if !got.Equal(p.now) {
		t.Fatalf("trusted time = %v, want %v", got, p.now)
	}

	// A timestamp over a different signature must fail the imprint check.
	pbBad := verify.NewTestParsedBundle(signedEnvelopeWithSig([]byte("other")), p.leaf.Raw, nil, token)
	if _, err := verify.TrustedTime(pbBad, tm); !errors.Is(err, verify.ErrTrustedTime) {
		t.Fatalf("mismatched imprint: got %v, want ErrTrustedTime", err)
	}
}
