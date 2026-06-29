package deploy

import (
	"context"
	"crypto/sha256"
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

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/target"
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
	ctfePub := filepath.Join(harness, "pki", "ctfe-pub.pem")
	for _, f := range []string{caddyRoot, rekorPub, tsaChain, ctfePub} {
		if _, statErr := os.Stat(f); statErr != nil {
			t.Fatalf("harness material missing (run make up / rekor-pubkey / tsa-certchain / ctlog-pubkey): %v", statErr)
		}
	}

	trust := endpoint.CABundle{Type: "caBundle", Path: caddyRoot}
	eps := lane.KeylessEndpoints{
		Fulcio: endpoint.HTTPS{Address: endpoint.MustParseURL("https://fulcio.127.0.0.1.sslip.io:5555"), Trust: trust},
		Rekor:  endpoint.HTTPS{Address: endpoint.MustParseURL("https://rekor.127.0.0.1.sslip.io:3003"), Trust: trust},
		TSA:    endpoint.HTTPS{Address: endpoint.MustParseURL("https://tsa.127.0.0.1.sslip.io:3004"), Trust: trust},
	}
	token, err := ambientIDToken()
	if err != nil {
		t.Fatalf("ambientIDToken: %v", err)
	}

	// One fixture bundle per statement kind the producer attaches as an OCI
	// referrer (Execute step 8b). The statements are the real projected
	// predicates (projectStatements) over a synthetic attestation, so the
	// goldens exercise predicate validation, not only envelope verification.
	// The lane identity and digest are taken from the golden lane fixture so a
	// UC2 verify against that same lane matches what the sealed predicate
	// carries.
	names := []string{"sealed", "engine-context", "informational"}
	lanePath, err := lane.NewFilePath(filepath.Join("..", "verify", "testdata", "golden", "lane.yaml"))
	if err != nil {
		t.Fatalf("golden lane path: %v", err)
	}
	goldenLane, laneDigest, err := lane.Parse(lanePath)
	if err != nil {
		t.Fatalf("parse golden lane: %v", err)
	}
	att := syntheticGoldenAttestation(laneDigest)
	sealed, engineCtx, info, err := projectStatements(att, goldenLane.OIDC, nil)
	if err != nil {
		t.Fatalf("projectStatements: %v", err)
	}
	statements := make([][]byte, len(names))
	for i, s := range []any{sealed, engineCtx, info} {
		statements[i], err = json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %s statement: %v", names[i], err)
		}
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
		goldenTrustedRoot(ctx, t, eps.Fulcio, rekorPub, tsaChain, ctfePub), 0o600); err != nil {
		t.Fatalf("write trusted_root.json: %v", err)
	}
	t.Logf("golden fixtures written to %s", goldenDir)
}

// syntheticGoldenAttestation builds a populated attestation for the golden
// fixtures: enough in each layer that the projected sealed, engine-context, and
// informational predicates are non-empty and exercise 3b's per-layer
// validation. laneDigest is sealed verbatim so a UC2 verify against the golden
// lane matches it.
func syntheticGoldenAttestation(laneDigest primitive.Digest) *Attestation {
	const artifactDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	return &Attestation{
		Sealed: Sealed{
			Artifacts: map[string]record.Artifact{
				"app": {Digest: "sha256:" + artifactDigest},
			},
			Target: target.Deploy{
				ID:          "golden-target",
				Type:        "registry",
				Description: "golden fixture deploy target",
			},
			LaneID:     "golden-lane",
			LaneDigest: laneDigest,
			Peers:      map[primitive.Identifier][]lane.Peer{},
		},
		EngineDependent: EngineDependent{
			PeerAttribution: map[primitive.Identifier][]string{"deploy": {"registry.example:443"}},
		},
		Informational: &Informational{
			PreStateDigest:  primitive.DigestFromHex(artifactDigest),
			PostStateDigest: primitive.DigestFromHex(artifactDigest),
		},
	}
}

// goldenTrustedRoot assembles the trusted_root.json the verifier consumes
// from the same harness materials liveTrustRoot uses -- the Fulcio chain via
// GET /api/v2/trustBundle over the pinned TLS client, the exported Rekor log
// public key, and the fetched TSA certificate chain -- but serialized as a
// protojson trustrootpb.TrustedRoot instead of sigstore-go's root.TrustedRoot.
// The last certificate of each chain is the trust anchor.
func goldenTrustedRoot(ctx context.Context, t *testing.T, fulcioEp endpoint.HTTPS, rekorPubPath, tsaChainPath, ctfePubPath string) []byte {
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

	ctfePEM, err := os.ReadFile(filepath.Clean(ctfePubPath))
	if err != nil {
		t.Fatalf("read ctfe public key: %v", err)
	}
	ctfeBlock, _ := pem.Decode(ctfePEM)
	if ctfeBlock == nil {
		t.Fatalf("ctfe public key is not PEM")
	}
	// RFC6962 CT log id is sha256(DER SubjectPublicKeyInfo), i.e. the PEM body
	// of an openssl `ec -pubout` PUBLIC KEY block. This differs from the Rekor
	// v2 C2SP signed-note key id computed by sha256LogID above.
	ctLogID := sha256.Sum256(ctfeBlock.Bytes)

	tr := &trustrootpb.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		CertificateAuthorities: []*trustrootpb.CertificateAuthority{{
			Uri:       fulcioEp.Address.URL(),
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
		Ctlogs: []*trustrootpb.TransparencyLogInstance{{
			BaseUrl:       "https://ct.127.0.0.1.sslip.io:6962/strike-ct",
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   ctfeBlock.Bytes,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				// The ctfe key has no certificate validity of its own; the
				// Fulcio root NotBefore is a safe lower bound.
				ValidFor: &protocommon.TimeRange{
					Start: timestamppb.New(fulcioRoot.NotBefore),
				},
			},
			LogId: &protocommon.LogId{KeyId: ctLogID[:]},
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
func fetchFulcioChain(ctx context.Context, t *testing.T, fulcioEp endpoint.HTTPS) []*x509.Certificate {
	t.Helper()
	client, err := httpClientFor(fulcioEp)
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
