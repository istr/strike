// Command gengolden regenerates the keyless verifier's golden fixtures in
// internal/verify/testdata/golden from the local sigstore harness. It is a
// deliberate, operator-invoked action, not a test: it produces three real
// statement bundles and the matching trusted_root.json, and it asserts nothing.
// See internal/verify/testdata/golden/README.md for when to run it and what the
// regenerated set must satisfy.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// Harness coordinates. These mirror test/sigstore-local's Caddy routes; they
// are configuration of that harness, not a rule the producer and verifier must
// agree on.
const (
	harnessIssuer = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
	fulcioURL     = "https://fulcio.127.0.0.1.sslip.io:5555"
	rekorURL      = "https://rekor.127.0.0.1.sslip.io:3003"
	tsaURL        = "https://tsa.127.0.0.1.sslip.io:3004"
)

// goldenNames are the fixture basenames, positionally aligned with the
// statements ProjectStatements returns.
var goldenNames = []string{"sealed", "engine-dependent", "informational"}

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

	trust, trustErr := testutil.CertificateFromPEMFile(caddyRoot)
	if trustErr != nil {
		return fmt.Errorf("golden trust anchor: %w", trustErr)
	}
	eps := lane.KeylessEndpoints{
		Fulcio: endpoint.HTTPS{Address: endpoint.MustParseURL(fulcioURL), Trust: trust},
		Rekor:  endpoint.HTTPS{Address: endpoint.MustParseURL(rekorURL), Trust: trust},
		TSA:    endpoint.HTTPS{Address: endpoint.MustParseURL(tsaURL), Trust: trust},
	}
	token, err := testutil.FetchIDToken(ctx, harnessIssuer, testutil.HarnessBuilderClient, caddyRoot)
	if err != nil {
		return err
	}

	goldenDir := filepath.Join(root, "internal", "verify", "testdata", "golden")
	bundles, err := statementBundles(ctx, eps, dialer, token, goldenDir)
	if err != nil {
		return err
	}
	fulcioClient, err := deploy.HTTPClientFor(eps.Fulcio, dialer)
	if err != nil {
		return fmt.Errorf("fulcio client: %w", err)
	}
	trustedRoot, err := testutil.HarnessTrustedRoot(ctx, fulcioClient, eps.Fulcio.Address.URL(), harness)
	if err != nil {
		return err
	}

	// Every payload exists before the first byte is written, so a harness
	// failure leaves the checked-in set whole rather than partly replaced.
	tree, err := os.OpenRoot(goldenDir)
	if err != nil {
		return fmt.Errorf("open golden dir: %w", err)
	}
	defer closer.Warn(tree, "golden dir")
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
	return deploy.ProduceKeylessBundles(ctx, eps, dialer, lane.NewSecretString(token), goldenLane.OIDC, statements)
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
			Peers:      map[primitive.Identifier][]endpoint.Endpoint{},
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
