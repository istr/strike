package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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
// oracle, against the golden trust root. Returns nil on accept.
func sigstoreAccepts(t *testing.T, bundleJSON []byte) error {
	t.Helper()
	tr, err := root.NewTrustedRootFromPath(filepath.Join(goldenDir(t), "trusted_root.json"))
	if err != nil {
		t.Fatalf("sigstore trusted root: %v", err)
	}
	return sigstoreVerdict(t, tr, bundleJSON)
}

// sigstoreVerdict runs one bundle through sigstore-go against tr, enforcing an
// inclusion proof, a signed timestamp, and the SCT embedded in the Fulcio leaf.
// The verifier/policy construction mirrors keyless_live_internal_test.go.
// Returns nil on accept.
func sigstoreVerdict(t *testing.T, tr *root.TrustedRoot, bundleJSON []byte) error {
	t.Helper()
	verifier, err := sgverify.NewVerifier(tr,
		sgverify.WithTransparencyLog(1),
		sgverify.WithSignedTimestamps(1),
		sgverify.WithSignedCertificateTimestamps(1),
	)
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

	// Trust-root mutation: dropping the CT log must make sigstore-go reject the
	// same golden it otherwise accepts. Removing the entry at the JSON level
	// leaves every other anchor byte-identical, so a rejection can only come
	// from the SCT check. Without this case, SCT enforcement could stop and
	// every test would stay green.
	t.Run("no-ctlogs", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Clean(filepath.Join(goldenDir(t), "trusted_root.json")))
		if err != nil {
			t.Fatalf("read trusted_root.json: %v", err)
		}
		var doc map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal(raw, &doc); unmarshalErr != nil {
			t.Fatalf("unmarshal trusted root: %v", unmarshalErr)
		}
		if _, ok := doc["ctlogs"]; !ok {
			t.Fatal("golden trusted root carries no ctlogs entry")
		}
		delete(doc, "ctlogs")
		stripped, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal stripped trusted root: %v", err)
		}
		tr, err := root.NewTrustedRootFromJSON(stripped)
		if err != nil {
			t.Fatalf("stripped trusted root: %v", err)
		}
		if verifyErr := sigstoreVerdict(t, tr, golden); verifyErr == nil {
			t.Error("sigstore-go accepted a bundle whose CT log is not in the trust root")
		}
		// strike fails earlier and harder: a trust root carrying no CT log is
		// not usable material at all, so the rejection is at the trusted-root
		// layer rather than at verification time.
		if _, parseErr := verify.ParseTrustedRoot(stripped); !errors.Is(parseErr, verify.ErrTrustedRoot) {
			t.Errorf("strike accepted a trust root with no CT log: %v", parseErr)
		}
	})
}

// mutatedTrustRoot applies fn to the golden trust root's single ctlogs entry
// and returns the re-encoded document. Every other anchor stays byte-identical
// and every signature in the bundle stays intact, so a rejection downstream can
// only come from the SCT layer.
func mutatedTrustRoot(t *testing.T, fn func(map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(goldenDir(t), "trusted_root.json")))
	if err != nil {
		t.Fatalf("read trusted_root.json: %v", err)
	}
	var doc map[string]any
	if unmarshalErr := json.Unmarshal(raw, &doc); unmarshalErr != nil {
		t.Fatalf("unmarshal trusted root: %v", unmarshalErr)
	}
	ctlogs, ok := doc["ctlogs"].([]any)
	if !ok || len(ctlogs) != 1 {
		t.Fatal("golden trusted root does not carry exactly one ctlogs entry")
	}
	entry, ok := ctlogs[0].(map[string]any)
	if !ok {
		t.Fatal("ctlogs entry is not an object")
	}
	fn(entry)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal mutated trust root: %v", err)
	}
	return out
}

// freshP256SPKI returns the DER SubjectPublicKeyInfo of a throwaway P-256 key,
// used as a CT log key the golden SCT was never signed with.
func freshP256SPKI(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return der
}

// TestGoldenCTMutations changes one field of the golden trust root's CT entry
// at a time and requires strike to reject the golden bundle it otherwise
// accepts. Without these cases the SCT layer could stop enforcing and every
// other test would stay green.
func TestGoldenCTMutations(t *testing.T) {
	golden := readGolden(t, "sealed")
	cases := []struct {
		mutate func(map[string]any)
		name   string
	}{
		{func(e map[string]any) {
			e["logId"] = map[string]any{"keyId": base64.StdEncoding.EncodeToString(make([]byte, 32))}
		}, "unknown-log-id"},
		{func(e map[string]any) {
			pk, ok := e["publicKey"].(map[string]any)
			if !ok {
				t.Fatal("ctlogs entry carries no publicKey object")
			}
			pk["rawBytes"] = base64.StdEncoding.EncodeToString(freshP256SPKI(t))
		}, "key-did-not-sign-the-sct"},
		{func(e map[string]any) {
			pk, ok := e["publicKey"].(map[string]any)
			if !ok {
				t.Fatal("ctlogs entry carries no publicKey object")
			}
			pk["validFor"] = map[string]any{
				"start": "2000-01-01T00:00:00Z",
				"end":   "2000-01-02T00:00:00Z",
			}
		}, "window-excludes-the-sct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := verify.ParseTrustedRoot(mutatedTrustRoot(t, tc.mutate))
			if err != nil {
				t.Fatalf("ParseTrustedRoot: %v", err)
			}
			_, verifyErr := verify.New(tm, goldenIdentity, goldenIssuer).Verify(golden)
			if !errors.Is(verifyErr, verify.ErrSCT) {
				t.Errorf("got %v, want ErrSCT", verifyErr)
			}
		})
	}
}

// flip inverts the first byte of b in place (no-op on empty input).
func flip(b []byte) {
	if len(b) > 0 {
		b[0] ^= 0xff
	}
}
