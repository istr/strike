package deploy

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/wire"
)

const (
	liveIssuer   = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
	liveIdentity = "tester@strike.localhost"
	// liveRekorOrigin is the checkpoint origin the harness Rekor signs
	// (--hostname=rekor.localhost). sigstore-go matches it against the
	// hostname of the trust root's BaseURL, so the BaseURL must use this
	// host even though the producer dials the sslip.io endpoint.
	liveRekorOrigin  = "rekor.localhost"
	liveRekorBaseURL = "https://" + liveRekorOrigin
	// liveCTBaseURL mirrors the harness CT route. Nothing dials it: the SCT is
	// embedded in the Fulcio leaf and checked offline against the log key. The
	// field exists so the assembled trust root matches the generated one.
	liveCTBaseURL = "https://ct.127.0.0.1.sslip.io:6962/strike-ct"
)

// liveStatement builds a minimal in-toto statement with a distinct subject
// digest per index, returning the statement and the hex digest.
func liveStatement(i int) ([]byte, string) {
	digest := fmt.Sprintf("%064x", i+1)
	stmt := fmt.Sprintf(`{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "live-%d.bin", "digest": {"sha256": "%s"}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {}
}`, i, digest)
	return []byte(stmt), digest
}

// TestKeylessLive produces real bundles against the TLS-only local sigstore
// harness and verifies them with sigstore-go against a trust root assembled
// from harness materials. The OIDC id_token is minted in-test from the
// harness Keycloak, so no token env is needed. Bring-up:
//
//	cd test/sigstore-local && make up
//	go test ./internal/deploy -run TestKeylessLive -v
//
// A harness whose containers exist but are stopped is restarted by the test
// itself, and the timestamp certificate chain is re-exported with it.
// Creating the harness stays an operator action.
//
// The harness is a prerequisite: the test runs by default and fails fast
// when it is down; set STRIKE_INTEGRATION=0 to skip.
func TestKeylessLive(t *testing.T) {
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, testutil.RequireEngine(t), harness)
	caddyRoot := filepath.Join(harness, "pki", "caddy-root.crt")
	rekorPub := filepath.Join(harness, "pki", "rekor-ed25519-pub.pem")
	tsaChain := filepath.Join(harness, "pki", "tsa-certchain.pem")
	ctfePub := filepath.Join(harness, "pki", "ctfe-pub.pem")
	for _, f := range []string{caddyRoot, rekorPub, tsaChain, ctfePub} {
		if _, statErr := os.Stat(f); statErr != nil {
			t.Fatalf("harness material missing (run make up / rekor-pubkey / tsa-certchain / ctlog-pubkey): %v", statErr)
		}
	}
	t.Setenv("SIGSTORE_ID_TOKEN", testutil.MintIDToken(t, liveIssuer, caddyRoot))

	trust := endpoint.CABundle{Type: "caBundle", Path: primitive.AbsPath(caddyRoot)}
	eps := lane.KeylessEndpoints{
		Fulcio: endpoint.HTTPS{Address: endpoint.MustParseURL("https://fulcio.127.0.0.1.sslip.io:5555"), Trust: trust},
		Rekor:  endpoint.HTTPS{Address: endpoint.MustParseURL("https://rekor.127.0.0.1.sslip.io:3003"), Trust: trust},
		TSA:    endpoint.HTTPS{Address: endpoint.MustParseURL("https://tsa.127.0.0.1.sslip.io:3004"), Trust: trust},
	}

	token, err := ambientIDToken()
	if err != nil {
		t.Fatalf("ambientIDToken: %v", err)
	}

	statements := make([][]byte, 3)
	digests := make([]string, 3)
	for i := range statements {
		statements[i], digests[i] = liveStatement(i)
	}

	ctx := context.Background()
	bundles, err := ProduceKeylessBundles(ctx, eps, token, statements)
	if err != nil {
		t.Fatalf("ProduceKeylessBundles: %v", err)
	}
	if len(bundles) != len(statements) {
		t.Fatalf("got %d bundles, want %d", len(bundles), len(statements))
	}

	tr := liveTrustRoot(ctx, t, eps.Fulcio, rekorPub, tsaChain, ctfePub)
	certID, err := verify.NewShortCertificateIdentity(liveIssuer, "", liveIdentity, "")
	if err != nil {
		t.Fatalf("NewShortCertificateIdentity: %v", err)
	}
	verifier, err := verify.NewVerifier(tr,
		verify.WithTransparencyLog(1),
		verify.WithSignedTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	for i, bundleJSON := range bundles {
		var pb protobundle.Bundle
		if err := protojson.Unmarshal(bundleJSON, &pb); err != nil {
			t.Fatalf("bundle %d: protojson: %v", i, err)
		}
		b, err := bundle.NewBundle(&pb)
		if err != nil {
			t.Fatalf("bundle %d: NewBundle: %v", i, err)
		}
		digestBytes, err := hex.DecodeString(digests[i])
		if err != nil {
			t.Fatalf("bundle %d: digest: %v", i, err)
		}
		policy := verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digestBytes),
			verify.WithCertificateIdentity(certID),
		)
		if _, err := verifier.Verify(b, policy); err != nil {
			t.Fatalf("bundle %d failed sigstore-go verification: %v", i, err)
		}
	}
}

// liveTrustRoot assembles a sigstore-go trust root from harness materials:
// the Fulcio root via GET /api/v2/trustBundle over the pinned TLS client,
// the exported Rekor log public key, the fetched TSA certificate chain, and
// the exported CT log public key.
// Caveats: the trust root BaseURL hostname must equal the checkpoint origin;
// Ed25519 SignatureHashFunc is crypto.Hash(0) (pure, no prehash); the log ID
// is the non-truncated C2SP signed-note key ID, sha256(origin + "\n" + 0x01 +
// raw ed25519 pubkey) -- NOT the sha256 of the PKIX DER (prefix 1e050d3e).
// The CT log ID is the other derivation -- RFC6962 sha256(DER
// SubjectPublicKeyInfo) -- which is the value the SCT embedded in the Fulcio
// leaf names. Both log entries carry a lower validity bound only, matching the
// generated trust root, where the log keys have no end date and sigstore-go
// leaves the field zero.
func liveTrustRoot(ctx context.Context, t *testing.T, fulcioEp endpoint.HTTPS, rekorPubPath, tsaChainPath, ctfePubPath string) *root.TrustedRoot {
	t.Helper()

	client, err := HTTPClientFor(fulcioEp)
	if err != nil {
		t.Fatalf("fulcio client: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fulcioEp.Address.URL()+"/api/v2/trustBundle", nil)
	if err != nil {
		t.Fatalf("trustBundle request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("trustBundle fetch: %v", err)
	}
	defer closeKeylessBody(resp)
	var tb struct {
		Chains []struct {
			Certificates []string `json:"certificates"`
		} `json:"chains"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&tb); decErr != nil {
		t.Fatalf("trustBundle decode: %v", decErr)
	}
	if len(tb.Chains) == 0 || len(tb.Chains[0].Certificates) == 0 {
		t.Fatalf("trustBundle has no certificates")
	}
	var chain []*x509.Certificate
	for _, p := range tb.Chains[0].Certificates {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			t.Fatalf("trustBundle certificate is not PEM")
		}
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr != nil {
			t.Fatalf("parse fulcio certificate: %v", certErr)
		}
		chain = append(chain, cert)
	}
	fulcioRoot := chain[len(chain)-1]
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:                fulcioRoot,
		Intermediates:       chain[:len(chain)-1],
		ValidityPeriodStart: fulcioRoot.NotBefore,
		ValidityPeriodEnd:   fulcioRoot.NotAfter,
		URI:                 fulcioEp.Address.URL(),
	}

	pubPEM, err := os.ReadFile(filepath.Clean(rekorPubPath))
	if err != nil {
		t.Fatalf("read rekor public key: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("rekor public key is not PEM")
	}
	edKey, err := wire.ParseEd25519PKIX(block.Bytes)
	if err != nil {
		t.Fatalf("parse rekor public key: %v", err)
	}
	logID := wire.NoteKeyID(liveRekorOrigin, edKey)
	tlog := &root.TransparencyLog{
		BaseURL:             liveRekorBaseURL,
		ID:                  logID,
		ValidityPeriodStart: clock.Unix(0, 0),
		HashFunc:            crypto.SHA256,
		PublicKey:           edKey,
		SignatureHashFunc:   crypto.Hash(0),
	}

	chainPEM, err := os.ReadFile(filepath.Clean(tsaChainPath))
	if err != nil {
		t.Fatalf("read tsa chain: %v", err)
	}
	var tsaCerts []*x509.Certificate
	rest := chainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		cert, certErr := x509.ParseCertificate(b.Bytes)
		if certErr != nil {
			t.Fatalf("parse tsa certificate: %v", certErr)
		}
		tsaCerts = append(tsaCerts, cert)
	}
	if len(tsaCerts) < 2 {
		t.Fatalf("tsa chain has %d certificates, want >= 2", len(tsaCerts))
	}
	tsaRoot := tsaCerts[len(tsaCerts)-1]
	tsaAuthority := &root.SigstoreTimestampingAuthority{
		Root:                tsaRoot,
		Intermediates:       tsaCerts[1 : len(tsaCerts)-1],
		Leaf:                tsaCerts[0],
		ValidityPeriodStart: tsaRoot.NotBefore,
		ValidityPeriodEnd:   tsaRoot.NotAfter,
	}

	ctfePEM, err := os.ReadFile(filepath.Clean(ctfePubPath))
	if err != nil {
		t.Fatalf("read ct log public key: %v", err)
	}
	ctfeBlock, _ := pem.Decode(ctfePEM)
	if ctfeBlock == nil {
		t.Fatalf("ct log public key is not PEM")
	}
	ctfeKey, err := x509.ParsePKIXPublicKey(ctfeBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ct log public key: %v", err)
	}
	ctLogID := sha256.Sum256(ctfeBlock.Bytes)
	ctLog := &root.TransparencyLog{
		BaseURL:             liveCTBaseURL,
		ID:                  ctLogID[:],
		ValidityPeriodStart: clock.Unix(0, 0),
		HashFunc:            crypto.SHA256,
		PublicKey:           ctfeKey,
		SignatureHashFunc:   crypto.SHA256,
	}

	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{fulcioCA},
		map[string]*root.TransparencyLog{hex.EncodeToString(ctLogID[:]): ctLog},
		[]root.TimestampingAuthority{tsaAuthority},
		map[string]*root.TransparencyLog{hex.EncodeToString(logID): tlog},
	)
	if err != nil {
		t.Fatalf("NewTrustedRoot: %v", err)
	}
	return tr
}
