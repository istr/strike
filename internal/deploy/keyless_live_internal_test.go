package deploy

import (
	"context"
	"crypto"
	"crypto/ed25519"
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
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
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
// from harness materials. Bring-up:
//
//	cd test/sigstore-local && make up && make rekor-pubkey && make tsa-certchain
//	SIGSTORE_ID_TOKEN="$(make -s -C test/sigstore-local token)" \
//	  go test ./internal/deploy -run TestKeylessLive -v
func TestKeylessLive(t *testing.T) {
	if os.Getenv("SIGSTORE_ID_TOKEN") == "" {
		t.Skip("SIGSTORE_ID_TOKEN not set; see test comment for harness bring-up")
	}
	harness, err := filepath.Abs(filepath.Join("..", "..", "test", "sigstore-local"))
	if err != nil {
		t.Fatalf("resolve harness dir: %v", err)
	}
	caddyRoot := filepath.Join(harness, "pki", "caddy-root.crt")
	rekorPub := filepath.Join(harness, "pki", "rekor-ed25519-pub.pem")
	tsaChain := filepath.Join(harness, "pki", "tsa-certchain.pem")
	for _, f := range []string{caddyRoot, rekorPub, tsaChain} {
		if _, statErr := os.Stat(f); statErr != nil {
			t.Fatalf("harness material missing (run make up / rekor-pubkey / tsa-certchain): %v", statErr)
		}
	}

	trust := transport.CABundleTrust{Mode: "ca_bundle", Path: caddyRoot}
	eps := lane.KeylessEndpoints{
		Fulcio: transport.HTTPSEndpoint{URL: "https://fulcio.127.0.0.1.sslip.io:5555", Trust: trust},
		Rekor:  transport.HTTPSEndpoint{URL: "https://rekor.127.0.0.1.sslip.io:3003", Trust: trust},
		TSA:    transport.HTTPSEndpoint{URL: "https://tsa.127.0.0.1.sslip.io:3004", Trust: trust},
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
	bundles, err := produceKeylessBundles(ctx, eps, token, statements)
	if err != nil {
		t.Fatalf("produceKeylessBundles: %v", err)
	}
	if len(bundles) != len(statements) {
		t.Fatalf("got %d bundles, want %d", len(bundles), len(statements))
	}

	tr := liveTrustRoot(ctx, t, eps.Fulcio, rekorPub, tsaChain)
	certID, err := verify.NewShortCertificateIdentity(liveIssuer, "", liveIdentity, "")
	if err != nil {
		t.Fatalf("NewShortCertificateIdentity: %v", err)
	}
	verifier, err := verify.NewVerifier(tr,
		verify.WithTransparencyLog(1),
		verify.WithSignedTimestamps(1),
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
// the exported Rekor log public key, and the fetched TSA certificate chain.
// R1 spike caveats applied: the trust root BaseURL hostname must equal the
// checkpoint origin; Ed25519 SignatureHashFunc is crypto.Hash(0) (pure, no
// prehash); the log ID is the SHA-256 of the DER-encoded public key.
func liveTrustRoot(ctx context.Context, t *testing.T, fulcioEp transport.HTTPSEndpoint, rekorPubPath, tsaChainPath string) *root.TrustedRoot {
	t.Helper()

	client, err := httpClientFor(fulcioEp)
	if err != nil {
		t.Fatalf("fulcio client: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fulcioEp.URL+"/api/v2/trustBundle", nil)
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
		URI:                 fulcioEp.URL,
	}

	pubPEM, err := os.ReadFile(filepath.Clean(rekorPubPath))
	if err != nil {
		t.Fatalf("read rekor public key: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("rekor public key is not PEM")
	}
	rekorKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse rekor public key: %v", err)
	}
	edKey, ok := rekorKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("rekor public key is %T, want ed25519", rekorKey)
	}
	logID := sha256LogID(liveRekorOrigin, edKey)
	tlog := &root.TransparencyLog{
		BaseURL:             liveRekorBaseURL,
		ID:                  logID,
		ValidityPeriodStart: clock.Unix(0, 0),
		ValidityPeriodEnd:   clock.Unix(1<<40, 0),
		HashFunc:            crypto.SHA256,
		PublicKey:           rekorKey,
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

	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{fulcioCA},
		nil,
		[]root.TimestampingAuthority{tsaAuthority},
		map[string]*root.TransparencyLog{hex.EncodeToString(logID): tlog},
	)
	if err != nil {
		t.Fatalf("NewTrustedRoot: %v", err)
	}
	return tr
}

// sha256LogID computes the Rekor v2 log ID: the non-truncated C2SP
// signed-note key ID -- SHA-256 over origin, newline, the Ed25519
// algorithm byte (0x01), and the raw public key (rekor-tiles pkg/note).
func sha256LogID(origin string, pub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(append([]byte(origin+"\n\x01"), pub...))
	return sum[:]
}
