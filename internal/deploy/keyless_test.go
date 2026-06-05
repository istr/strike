package deploy_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/deploy"
)

// fixtureStatement is a minimal valid SLSA provenance v1 in-toto statement.
var fixtureStatement = []byte(`{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "artifact.bin",
      "digest": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {}
}`)

func TestKeylessCrossval(t *testing.T) {
	const (
		identity = "tester@strike.localhost"
		issuer   = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
	)

	// 1. Stand up a virtual sigstore stack.
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	// 2. Generate a leaf certificate bound to an ephemeral key.
	leafCert, signer, err := vs.GenerateLeafCert(identity, issuer)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("signer is %T, want *ecdsa.PrivateKey", signer)
	}

	// 3. Sign the fixture statement with strike's keyless DER signing.
	env, sig, err := deploy.SignStatementKeyless(fixtureStatement, key)
	if err != nil {
		t.Fatalf("SignStatementKeyless: %v", err)
	}

	// 4. Build a Rekor tlog entry via the harness. GenerateTlogEntry expects
	// a go-securesystemslib/dsse.Envelope (base64 payload and sig strings),
	// so convert from the protobuf envelope.
	sslEnv := &ssldsse.Envelope{
		PayloadType: env.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(env.Payload),
		Signatures: []ssldsse.Signature{
			{Sig: base64.StdEncoding.EncodeToString(env.Signatures[0].Sig)},
		},
	}
	entry, err := vs.GenerateTlogEntry(leafCert, sslEnv, sig, int64(0), true)
	if err != nil {
		t.Fatalf("GenerateTlogEntry: %v", err)
	}
	tle := entry.TransparencyLogEntry()
	// The harness leaves KindVersion nil; real Rekor sets it. Patch it so
	// the bundle round-trips through ParseTransparencyLogEntry.
	if tle.KindVersion == nil {
		tle.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
	}

	// 5. Get an RFC3161 timestamp over the signature.
	rfc3161, err := vs.TimestampResponse(sig)
	if err != nil {
		t.Fatalf("TimestampResponse: %v", err)
	}

	// 6. Assemble the sigstore v0.3 bundle with strike's assembler.
	bundleJSON, err := deploy.AssembleKeylessBundle(env, leafCert.Raw, tle, rfc3161)
	if err != nil {
		t.Fatalf("AssembleKeylessBundle: %v", err)
	}

	// 7. Parse back through protojson -> bundle.NewBundle.
	var pb protobundle.Bundle
	err = protojson.Unmarshal(bundleJSON, &pb)
	if err != nil {
		t.Fatalf("protojson.Unmarshal bundle: %v", err)
	}
	b, err := bundle.NewBundle(&pb)
	if err != nil {
		t.Fatalf("bundle.NewBundle: %v", err)
	}

	// 8. Verify with sigstore-go: transparency log + signed timestamps.
	certID, err := verify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		t.Fatalf("NewShortCertificateIdentity: %v", err)
	}
	verifier, err := verify.NewVerifier(vs,
		verify.WithTransparencyLog(1),
		verify.WithSignedTimestamps(1),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	policy := verify.NewPolicy(verify.WithoutArtifactUnsafe(),
		verify.WithCertificateIdentity(certID),
	)
	if _, err := verifier.Verify(b, policy); err != nil {
		t.Fatalf("strike-signed bundle failed sigstore-go verification: %v", err)
	}
}
