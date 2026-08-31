// Command gengolden regenerates the keyless verifier's golden fixtures in
// internal/verify/testdata/golden from the local sigstore harness. It is a
// deliberate, operator-invoked action, not a test: it produces three real
// statement bundles and the matching trusted_root.json, and it asserts nothing.
// See internal/verify/testdata/golden/README.md for when to run it and what the
// regenerated set must satisfy.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
	"github.com/istr/strike/internal/wire"
)

// Harness coordinates. These mirror test/sigstore-local's Caddy routes and the
// checkpoint origin its Rekor signs; they are configuration of that harness,
// not a rule the producer and verifier must agree on.
const (
	harnessIssuer    = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
	rekorOrigin      = "rekor.localhost"
	rekorBaseURL     = "https://" + rekorOrigin
	ctBaseURL        = "https://ct.127.0.0.1.sslip.io:6962/strike-ct"
	fulcioURL        = "https://fulcio.127.0.0.1.sslip.io:5555"
	rekorURL         = "https://rekor.127.0.0.1.sslip.io:3003"
	tsaURL           = "https://tsa.127.0.0.1.sslip.io:3004"
	trustedRootMedia = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
)

// goldenNames are the fixture basenames, positionally aligned with the
// statements ProjectStatements returns.
var goldenNames = []string{"sealed", "engine-context", "informational"}

func main() {
	log.SetFlags(0)
	log.SetPrefix("gengolden: ")
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	root, err := testutil.ModuleRoot()
	if err != nil {
		return err
	}
	harness, err := testutil.FindHarnessDir()
	if err != nil {
		return fmt.Errorf("%w (run make up in test/sigstore-local)", err)
	}
	caddyRoot := filepath.Join(harness, "pki", "caddy-root.crt")
	rekorPub := filepath.Join(harness, "pki", "rekor-ed25519-pub.pem")
	tsaChain := filepath.Join(harness, "pki", "tsa-certchain.pem")
	ctfePub := filepath.Join(harness, "pki", "ctfe-pub.pem")
	for _, f := range []string{caddyRoot, rekorPub, tsaChain, ctfePub} {
		if _, statErr := os.Stat(f); statErr != nil {
			return fmt.Errorf("harness material missing (run make up / rekor-pubkey / tsa-certchain / ctlog-pubkey): %w", statErr)
		}
	}

	dialer, err := testutil.HarnessDialer(harness)
	if err != nil {
		return err
	}

	trust := endpoint.CABundle{Type: "caBundle", Path: primitive.AbsPath(caddyRoot)}
	eps := lane.KeylessEndpoints{
		Fulcio: endpoint.HTTPS{Address: endpoint.MustParseURL(fulcioURL), Trust: trust},
		Rekor:  endpoint.HTTPS{Address: endpoint.MustParseURL(rekorURL), Trust: trust},
		TSA:    endpoint.HTTPS{Address: endpoint.MustParseURL(tsaURL), Trust: trust},
	}
	token, err := testutil.FetchIDToken(ctx, harnessIssuer, caddyRoot)
	if err != nil {
		return err
	}

	goldenDir := filepath.Join(root, "internal", "verify", "testdata", "golden")
	bundles, err := statementBundles(ctx, eps, dialer, token, goldenDir)
	if err != nil {
		return err
	}
	trustedRoot, err := assembleTrustedRoot(ctx, eps.Fulcio, dialer, rekorPub, tsaChain, ctfePub)
	if err != nil {
		return err
	}

	// Every payload exists before the first byte is written, so a harness
	// failure leaves the checked-in set whole rather than partly replaced.
	tree, err := os.OpenRoot(goldenDir)
	if err != nil {
		return fmt.Errorf("open golden dir: %w", err)
	}
	defer func() {
		if closeErr := tree.Close(); closeErr != nil {
			log.Printf("WARN close golden dir: %v", closeErr)
		}
	}()
	for i, name := range goldenNames {
		if writeErr := tree.WriteFile(name+".sigstore.json", bundles[i], 0o600); writeErr != nil {
			return fmt.Errorf("write %s bundle: %w", name, writeErr)
		}
	}
	if writeErr := tree.WriteFile("trusted_root.json", trustedRoot, 0o600); writeErr != nil {
		return fmt.Errorf("write trusted_root.json: %w", writeErr)
	}
	log.Printf("golden fixtures written to %s", goldenDir)
	return nil
}

// statementBundles produces one fixture bundle per statement kind the producer
// attaches as an OCI referrer. The statements are the real projected predicates
// over a synthetic attestation, so the goldens exercise predicate validation and
// not only envelope verification. The lane identity and digest come from the
// golden lane fixture, so a UC2 verify against that same lane matches what the
// sealed predicate carries.
func statementBundles(ctx context.Context, eps lane.KeylessEndpoints, dialer *transport.Dialer, token, goldenDir string) ([][]byte, error) {
	lanePath, err := lane.NewFilePath(filepath.Join(goldenDir, "lane.yaml"))
	if err != nil {
		return nil, fmt.Errorf("golden lane path: %w", err)
	}
	goldenLane, _, laneDigest, err := lane.Parse(lanePath)
	if err != nil {
		return nil, fmt.Errorf("parse golden lane: %w", err)
	}
	sealed, engineCtx, info, err := deploy.ProjectStatements(syntheticAttestation(laneDigest), goldenLane.OIDC, nil)
	if err != nil {
		return nil, fmt.Errorf("project statements: %w", err)
	}
	statements := make([][]byte, len(goldenNames))
	for i, s := range []any{sealed, engineCtx, info} {
		statements[i], err = json.Marshal(s)
		if err != nil {
			return nil, fmt.Errorf("marshal %s statement: %w", goldenNames[i], err)
		}
	}
	return deploy.ProduceKeylessBundles(ctx, eps, dialer, token, statements)
}

// syntheticAttestation builds a populated attestation for the golden fixtures:
// enough in each layer that the projected sealed, engine-context, and
// informational predicates are non-empty and exercise the per-layer validation.
// laneDigest is sealed verbatim so a UC2 verify against the golden lane matches
// it.
func syntheticAttestation(laneDigest primitive.Digest) *deploy.Attestation {
	const artifactDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	return &deploy.Attestation{
		Sealed: deploy.Sealed{
			Artifacts: map[primitive.Identifier]record.Artifact{
				"app": {Digest: "sha256:" + artifactDigest},
			},
			LaneID:     "golden-lane",
			LaneDigest: laneDigest,
			Peers:      map[primitive.Identifier][]lane.Peer{},
		},
		EngineDependent: deploy.EngineDependent{
			PeerAttribution: map[primitive.Identifier][]endpoint.Authority{"deploy": {"registry.example:443"}},
		},
		Informational: &deploy.Informational{
			PreStateDigest:  primitive.DigestFromHex(artifactDigest),
			PostStateDigest: primitive.DigestFromHex(artifactDigest),
		},
	}
}

// trustMaterials are the harness inputs the trust root is assembled from,
// grouped so the proto construction stays one readable literal.
type trustMaterials struct {
	fulcioURI   string
	fulcioCerts []*x509.Certificate
	tsaCerts    []*x509.Certificate
	rekorKeyDER []byte
	rekorLogID  []byte
	ctfeKeyDER  []byte
	ctfeLogID   []byte
}

// assembleTrustedRoot builds the trusted_root.json the verifier consumes from
// the same harness materials the live keyless test uses -- the Fulcio chain via
// GET /api/v2/trustBundle over the pinned TLS client, the exported Rekor log
// public key, and the fetched TSA certificate chain.
func assembleTrustedRoot(ctx context.Context, fulcioEp endpoint.HTTPS, dialer *transport.Dialer, rekorPubPath, tsaChainPath, ctfePubPath string) ([]byte, error) {
	fulcioCerts, err := fulcioChain(ctx, fulcioEp, dialer)
	if err != nil {
		return nil, err
	}
	rekorBlock, err := readPEM(rekorPubPath, "rekor public key")
	if err != nil {
		return nil, err
	}
	edPub, err := wire.ParseEd25519PKIX(rekorBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rekor public key: %w", err)
	}
	tsaCerts, err := certChain(tsaChainPath, "tsa")
	if err != nil {
		return nil, err
	}
	if len(tsaCerts) < 2 {
		return nil, fmt.Errorf("tsa chain has %d certificates, want >= 2", len(tsaCerts))
	}
	ctfeBlock, err := readPEM(ctfePubPath, "ctfe public key")
	if err != nil {
		return nil, err
	}
	// RFC6962 CT log id is sha256(DER SubjectPublicKeyInfo), i.e. the PEM body
	// of an openssl `ec -pubout` PUBLIC KEY block. This differs from the Rekor
	// v2 C2SP signed-note key id computed by wire.NoteKeyID.
	ctLogID := sha256.Sum256(ctfeBlock.Bytes)

	out, err := protojson.Marshal(trustedRootProto(trustMaterials{
		fulcioURI:   fulcioEp.Address.URL(),
		fulcioCerts: fulcioCerts,
		tsaCerts:    tsaCerts,
		rekorKeyDER: rekorBlock.Bytes,
		rekorLogID:  wire.NoteKeyID(rekorOrigin, edPub),
		ctfeKeyDER:  ctfeBlock.Bytes,
		ctfeLogID:   ctLogID[:],
	}))
	if err != nil {
		return nil, fmt.Errorf("marshal trusted root: %w", err)
	}
	return out, nil
}

// trustedRootProto lays out the sigstore TrustedRoot. The last certificate of
// each chain is the trust anchor. Neither log key has a certificate validity of
// its own, and sigstore-go's trusted-root loader requires a start, so the Fulcio
// root NotBefore is used as a lower bound -- it precedes any entry this harness
// can have signed.
func trustedRootProto(m trustMaterials) *trustrootpb.TrustedRoot {
	fulcioRoot := m.fulcioCerts[len(m.fulcioCerts)-1]
	tsaRoot := m.tsaCerts[len(m.tsaCerts)-1]
	return &trustrootpb.TrustedRoot{
		MediaType: trustedRootMedia,
		CertificateAuthorities: []*trustrootpb.CertificateAuthority{{
			Uri:       m.fulcioURI,
			CertChain: &protocommon.X509CertificateChain{Certificates: rawCertificates(m.fulcioCerts)},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(fulcioRoot.NotBefore),
				End:   timestamppb.New(fulcioRoot.NotAfter),
			},
		}},
		TimestampAuthorities: []*trustrootpb.CertificateAuthority{{
			CertChain: &protocommon.X509CertificateChain{Certificates: rawCertificates(m.tsaCerts)},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(tsaRoot.NotBefore),
				End:   timestamppb.New(tsaRoot.NotAfter),
			},
		}},
		Tlogs: []*trustrootpb.TransparencyLogInstance{{
			BaseUrl:       rekorBaseURL,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   m.rekorKeyDER,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ED25519,
				ValidFor:   &protocommon.TimeRange{Start: timestamppb.New(fulcioRoot.NotBefore)},
			},
			LogId: &protocommon.LogId{KeyId: m.rekorLogID},
		}},
		Ctlogs: []*trustrootpb.TransparencyLogInstance{{
			BaseUrl:       ctBaseURL,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   m.ctfeKeyDER,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				ValidFor:   &protocommon.TimeRange{Start: timestamppb.New(fulcioRoot.NotBefore)},
			},
			LogId: &protocommon.LogId{KeyId: m.ctfeLogID},
		}},
	}
}

// fulcioChain fetches and parses the Fulcio certificate chain via
// GET /api/v2/trustBundle. The returned order is the served order (leaf-most
// first, trust anchor last).
func fulcioChain(ctx context.Context, fulcioEp endpoint.HTTPS, dialer *transport.Dialer) ([]*x509.Certificate, error) {
	client, err := deploy.HTTPClientFor(fulcioEp, dialer)
	if err != nil {
		return nil, fmt.Errorf("fulcio client: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fulcioEp.Address.URL()+"/api/v2/trustBundle", nil)
	if err != nil {
		return nil, fmt.Errorf("trustBundle request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustBundle fetch: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	var tb struct {
		Chains []struct {
			Certificates []string `json:"certificates"`
		} `json:"chains"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&tb); decErr != nil {
		return nil, fmt.Errorf("trustBundle decode: %w", decErr)
	}
	if len(tb.Chains) == 0 || len(tb.Chains[0].Certificates) == 0 {
		return nil, errors.New("trustBundle has no certificates")
	}
	var chain []*x509.Certificate
	for _, p := range tb.Chains[0].Certificates {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return nil, errors.New("trustBundle certificate is not PEM")
		}
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr != nil {
			return nil, fmt.Errorf("parse fulcio certificate: %w", certErr)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// readPEM reads a single-block PEM file, naming it in any error.
func readPEM(path, what string) (*pem.Block, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", what)
	}
	return block, nil
}

// certChain reads a concatenated PEM certificate chain in file order.
func certChain(path, what string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read %s chain: %w", what, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		cert, certErr := x509.ParseCertificate(b.Bytes)
		if certErr != nil {
			return nil, fmt.Errorf("parse %s certificate: %w", what, certErr)
		}
		certs = append(certs, cert)
	}
	return certs, nil
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
