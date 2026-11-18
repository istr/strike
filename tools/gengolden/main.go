// Command gengolden regenerates the keyless verifier's golden fixtures in
// internal/verify/testdata/golden from the local sigstore harness. It is a
// deliberate, operator-invoked action, not a test: it produces four real
// statement bundles and the matching trusted_root.json, and it asserts nothing.
// See internal/verify/testdata/golden/README.md for when to run it and what the
// regenerated set must satisfy.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing/fstest"

	"github.com/istr/strike/internal/clock"
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

// The synthetic deploy the goldens attest: the deploy step of the golden lane
// pushes its one artifact, the image arm goldenImage, to the registry target
// the lane declares. The produced and the pushed digest differ, as they do in
// a deploy, where the engine re-encodes the image on export.
const (
	goldenImage    = "app"
	producedDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	pushedDigest   = "2222222222222222222222222222222222222222222222222222222222222222"
)

// goldenNames are the fixture basenames, positionally aligned with the
// payloads deploy.StatementPayloads returns.
var goldenNames = []string{"sealed", "engine-dependent", "informational", "sbom"}

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

// statementBundles produces one fixture bundle per statement a registry deploy
// attaches as an OCI referrer: the three layer statements and the SBOM
// statement. The statements are the real projected predicates over a synthetic
// attestation, in the canonical form a deploy signs, so the goldens exercise
// predicate validation and not only envelope verification. The lane identity
// and digest come from the golden lane fixture, so a UC2 verify against that
// same lane matches what the sealed predicate carries.
func statementBundles(ctx context.Context, eps lane.KeylessEndpoints, dialer *transport.Dialer, token, goldenDir string) ([][]byte, error) {
	lanePath, err := lane.NewFilePath(filepath.Join(goldenDir, "lane.yaml"))
	if err != nil {
		return nil, fmt.Errorf("golden lane path: %w", err)
	}
	goldenLane, _, laneDigest, err := lane.Parse(lanePath)
	if err != nil {
		return nil, fmt.Errorf("parse golden lane: %w", err)
	}
	doc, err := goldenDocument()
	if err != nil {
		return nil, fmt.Errorf("golden document: %w", err)
	}
	statements, err := deploy.StatementPayloads(syntheticAttestation(laneDigest, doc), goldenLane.OIDC, nil, goldenImage, doc)
	if err != nil {
		return nil, err
	}
	return deploy.ProduceKeylessBundles(ctx, eps, dialer, lane.NewSecretString(token), goldenLane.OIDC, statements)
}

// goldenDocument catalogs a one-package filesystem into the document of the
// image arm, the way a registry deploy catalogs the pushed image: under the
// pushed digest, and at the Unix epoch, the source date of a run that sets
// none.
func goldenDocument() ([]byte, error) {
	fsys := fstest.MapFS{
		"var/lib/dpkg/status": &fstest.MapFile{
			Data: []byte("Package: libc6\nVersion: 2.36-9\nArchitecture: amd64\nStatus: install ok installed\n\n"),
		},
	}
	return deploy.GenerateImageSBOM(fsys, primitive.DigestFromHex(pushedDigest), clock.Unix(0, 0).UTC())
}

// syntheticAttestation builds a populated attestation for the golden fixtures:
// enough in each layer that the projected sealed, engine-context, and
// informational predicates are non-empty and exercise the per-layer validation.
// laneDigest is sealed verbatim so a UC2 verify against the golden lane matches
// it. The image arm is pushed, and its record carries the digest of doc, its
// SBOM document, so the sealed statement names the document the SBOM statement
// carries.
func syntheticAttestation(laneDigest primitive.Digest, doc []byte) *deploy.Attestation {
	docSum := sha256.Sum256(doc)
	return &deploy.Attestation{
		Sealed: deploy.Sealed{
			Artifacts: map[primitive.Identifier]record.Artifact{
				goldenImage: {
					Digest: "sha256:" + producedDigest,
					SBOM:   &record.SBOMSet{CycloneDX: primitive.DigestFromHex(hex.EncodeToString(docSum[:]))},
				},
			},
			Pushed: &deploy.PushedArtifact{
				Registry:   "registry.example.com",
				Repository: "golden",
				Digest:     "sha256:" + pushedDigest,
			},
			LaneID:     "golden-lane",
			LaneDigest: laneDigest,
			Peers:      map[primitive.Identifier][]endpoint.Endpoint{},
		},
		EngineDependent: deploy.EngineDependent{
			PeerAttribution: map[primitive.Identifier][]endpoint.Authority{"deploy": {"registry.example:443"}},
		},
		Informational: &deploy.Informational{
			PreStateDigest:  primitive.DigestFromHex(producedDigest),
			PostStateDigest: primitive.DigestFromHex(producedDigest),
		},
	}
}
