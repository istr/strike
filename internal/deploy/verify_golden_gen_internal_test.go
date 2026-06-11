package deploy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
)

// TestVerifyGoldenGenerate is the env-gated generator for the keyless
// verifier's golden fixtures (consumed by instruction 5a-ii's differential
// and tamper tests): it produces three real statement bundles against the
// local sigstore harness and assembles the matching trusted_root.json from
// harness materials, writing everything under
// internal/verify/testdata/golden/. It asserts nothing about verification;
// it only emits fixtures. Bring-up is identical to TestKeylessLive (see
// that test's comment); without SIGSTORE_ID_TOKEN it skips and writes
// nothing.
func TestVerifyGoldenGenerate(t *testing.T) {
	if os.Getenv("SIGSTORE_ID_TOKEN") == "" {
		t.Skip("SIGSTORE_ID_TOKEN not set; see TestKeylessLive for harness bring-up")
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

	// One fixture bundle per statement kind the producer attaches as an OCI
	// referrer (Execute step 8b).
	names := []string{"sealed", "engine-context", "informational"}
	statements := make([][]byte, len(names))
	for i := range names {
		statements[i], _ = liveStatement(i)
	}
	ctx := context.Background()
	bundles, err := produceKeylessBundles(ctx, eps, token, statements)
	if err != nil {
		t.Fatalf("produceKeylessBundles: %v", err)
	}

	goldenDir := filepath.Join("..", "verify", "testdata", "golden")
	if err := os.MkdirAll(goldenDir, 0o750); err != nil {
		t.Fatalf("create golden dir: %v", err)
	}
	for i, name := range names {
		if err := os.WriteFile(filepath.Join(goldenDir, name+".sigstore.json"), bundles[i], 0o600); err != nil {
			t.Fatalf("write %s bundle: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(goldenDir, "trusted_root.json"),
		goldenTrustedRoot(ctx, t, eps.Fulcio, rekorPub, tsaChain), 0o600); err != nil {
		t.Fatalf("write trusted_root.json: %v", err)
	}
	t.Logf("golden fixtures written to %s", goldenDir)
}

// goldenTrustedRoot assembles the trusted_root.json the verifier consumes
// from the same harness materials liveTrustRoot uses -- the Fulcio chain via
// GET /api/v2/trustBundle over the pinned TLS client, the exported Rekor log
// public key, and the fetched TSA certificate chain -- but serialized as a
// protojson trustrootpb.TrustedRoot instead of sigstore-go's root.TrustedRoot.
// The last certificate of each chain is the trust anchor.
func goldenTrustedRoot(ctx context.Context, t *testing.T, fulcioEp transport.HTTPSEndpoint, rekorPubPath, tsaChainPath string) []byte {
	t.Helper()

	fulcioCerts := fetchFulcioChain(ctx, t, fulcioEp)
	fulcioRoot := fulcioCerts[len(fulcioCerts)-1]

	pubPEM, err := os.ReadFile(filepath.Clean(rekorPubPath))
	if err != nil {
		t.Fatalf("read rekor public key: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("rekor public key is not PEM")
	}
	edPub, err := parseEd25519PKIX(block.Bytes)
	if err != nil {
		t.Fatalf("parse rekor public key: %v", err)
	}
	logID := sha256LogID(liveRekorOrigin, edPub)

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

	tr := &trustrootpb.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		CertificateAuthorities: []*trustrootpb.CertificateAuthority{{
			Uri:       fulcioEp.URL,
			CertChain: &protocommon.X509CertificateChain{Certificates: rawCertificates(fulcioCerts)},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(fulcioRoot.NotBefore),
				End:   timestamppb.New(fulcioRoot.NotAfter),
			},
		}},
		TimestampAuthorities: []*trustrootpb.CertificateAuthority{{
			CertChain: &protocommon.X509CertificateChain{Certificates: rawCertificates(tsaCerts)},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(tsaRoot.NotBefore),
				End:   timestamppb.New(tsaRoot.NotAfter),
			},
		}},
		Tlogs: []*trustrootpb.TransparencyLogInstance{{
			BaseUrl:       liveRekorBaseURL,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   block.Bytes,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ED25519,
				// sigstore-go's trusted-root loader requires a validity start
				// for the log key. The Ed25519 log key has no certificate
				// validity of its own; the Fulcio root NotBefore is a safe
				// lower bound (it precedes any entry signed in this harness).
				ValidFor: &protocommon.TimeRange{
					Start: timestamppb.New(fulcioRoot.NotBefore),
				},
			},
			LogId: &protocommon.LogId{KeyId: logID},
		}},
	}
	out, err := protojson.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal trusted root: %v", err)
	}
	return out
}

// fetchFulcioChain fetches and parses the Fulcio certificate chain via
// GET /api/v2/trustBundle, mirroring liveTrustRoot's fetch step. The
// returned order is the served order (leaf-most first, trust anchor last).
func fetchFulcioChain(ctx context.Context, t *testing.T, fulcioEp transport.HTTPSEndpoint) []*x509.Certificate {
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
	return chain
}

// rawCertificates converts parsed certificates to the proto chain entries,
// preserving order.
func rawCertificates(certs []*x509.Certificate) []*protocommon.X509Certificate {
	out := make([]*protocommon.X509Certificate, len(certs))
	for i, c := range certs {
		out[i] = &protocommon.X509Certificate{RawBytes: c.Raw}
	}
	return out
}
