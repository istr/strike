package verify_test

import (
	"os"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/istr/strike/internal/verify"
)

const (
	goldenIdentity = "tester@strike.localhost"
	goldenIssuer   = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
)

var goldenNames = []string{"sealed", "engine-context", "informational"}

func goldenDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "golden")
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(filepath.Join(goldenDir(t), name+".sigstore.json")))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return b
}

func goldenMaterial(t *testing.T) *verify.TrustedMaterial {
	t.Helper()
	trJSON, err := os.ReadFile(filepath.Clean(filepath.Join(goldenDir(t), "trusted_root.json")))
	if err != nil {
		t.Fatalf("read trusted_root.json: %v", err)
	}
	tm, err := verify.ParseTrustedRoot(trJSON)
	if err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
	}
	return tm
}

func strikeVerifier(t *testing.T) *verify.Verifier {
	t.Helper()
	return verify.New(goldenMaterial(t), goldenIdentity, goldenIssuer)
}

// sigstoreAccepts runs the bundle through sigstore-go as the differential
// oracle. The verifier/policy construction mirrors
// keyless_live_internal_test.go. Returns nil on accept.
func sigstoreAccepts(t *testing.T, bundleJSON []byte) error {
	t.Helper()
	tr, err := root.NewTrustedRootFromPath(filepath.Join(goldenDir(t), "trusted_root.json"))
	if err != nil {
		t.Fatalf("sigstore trusted root: %v", err)
	}
	verifier, err := sgverify.NewVerifier(tr, sgverify.WithTransparencyLog(1), sgverify.WithSignedTimestamps(1))
	if err != nil {
		t.Fatalf("sigstore NewVerifier: %v", err)
	}
	var pb protobundle.Bundle
	if uerr := protojson.Unmarshal(bundleJSON, &pb); uerr != nil {
		t.Fatalf("unmarshal bundle: %v", uerr)
	}
	b, err := bundle.NewBundle(&pb)
	if err != nil {
		return err
	}
	certID, err := sgverify.NewShortCertificateIdentity(goldenIssuer, "", goldenIdentity, "")
	if err != nil {
		t.Fatalf("NewShortCertificateIdentity: %v", err)
	}
	policy := sgverify.NewPolicy(
		sgverify.WithoutArtifactUnsafe(),
		sgverify.WithCertificateIdentity(certID),
	)
	_, err = verifier.Verify(b, policy)
	return err
}

func TestGoldenDifferentialAccept(t *testing.T) {
	sv := strikeVerifier(t)
	for _, name := range goldenNames {
		t.Run(name, func(t *testing.T) {
			golden := readGolden(t, name)
			if _, err := sv.Verify(golden); err != nil {
				t.Errorf("strike rejected a valid golden: %v", err)
			}
			if err := sigstoreAccepts(t, golden); err != nil {
				t.Errorf("sigstore-go rejected a valid golden: %v", err)
			}
		})
	}
}

// mutate decodes the golden bundle, applies fn to the proto, and re-marshals.
func mutate(t *testing.T, golden []byte, fn func(*protobundle.Bundle)) []byte {
	t.Helper()
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(golden, &pb); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fn(&pb)
	out, err := protojson.Marshal(&pb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestGoldenTamperMatrix(t *testing.T) {
	sv := strikeVerifier(t)
	// engine-context, not sealed: its inclusion proof carries a non-empty
	// audit path, so the proof-hash mutation has a hash to flip (sealed is
	// the single-leaf tree whose audit path is empty).
	golden := readGolden(t, "engine-context")

	// Cryptographic mutations: BOTH strike and sigstore-go must reject.
	cryptoCases := []struct {
		fn   func(*protobundle.Bundle)
		name string
	}{
		{func(b *protobundle.Bundle) { flip(b.GetDsseEnvelope().GetPayload()) }, "payload"},
		{func(b *protobundle.Bundle) { flip(b.GetDsseEnvelope().GetSignatures()[0].GetSig()) }, "signature"},
		{func(b *protobundle.Bundle) { flip(b.GetVerificationMaterial().GetCertificate().GetRawBytes()) }, "leaf-cert"},
		{func(b *protobundle.Bundle) {
			flip(b.GetVerificationMaterial().GetTlogEntries()[0].GetInclusionProof().GetHashes()[0])
		}, "proof-hash"},
	}
	for _, tc := range cryptoCases {
		t.Run("crypto/"+tc.name, func(t *testing.T) {
			bad := mutate(t, golden, tc.fn)
			if _, err := sv.Verify(bad); err == nil {
				t.Errorf("strike accepted a %s-tampered bundle", tc.name)
			}
			if err := sigstoreAccepts(t, bad); err == nil {
				t.Errorf("sigstore-go accepted a %s-tampered bundle", tc.name)
			}
		})
	}

	// Policy mutations: strike's own checks.
	t.Run("identity", func(t *testing.T) {
		wrong := verify.New(goldenMaterial(t), "attacker@evil", goldenIssuer)
		if _, err := wrong.Verify(golden); err == nil {
			t.Error("strike accepted a bundle under the wrong identity")
		}
	})
	t.Run("issuer", func(t *testing.T) {
		wrong := verify.New(goldenMaterial(t), goldenIdentity, "https://evil.example")
		if _, err := wrong.Verify(golden); err == nil {
			t.Error("strike accepted a bundle under the wrong issuer")
		}
	})
}

// flip inverts the first byte of b in place (no-op on empty input).
func flip(b []byte) {
	if len(b) > 0 {
		b[0] ^= 0xff
	}
}
