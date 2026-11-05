package deploy

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
)

const (
	liveIssuer   = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
	liveIdentity = "https://forge.strike.localhost/istr/strike/bootstrap/lane.cue@refs/heads/main"
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
	t.Setenv("SIGSTORE_ID_TOKEN", testutil.MintIDToken(t, liveIssuer, testutil.HarnessBuilderClient, caddyRoot))

	dialer, dialerErr := testutil.HarnessDialer(harness)
	if dialerErr != nil {
		t.Fatalf("harness dialer: %v", dialerErr)
	}

	trust, trustErr := testutil.CertificateFromPEMFile(caddyRoot)
	if trustErr != nil {
		t.Fatalf("harness root anchor: %v", trustErr)
	}
	eps := lane.KeylessEndpoints{
		Fulcio: endpoint.HTTPS{Address: endpoint.MustParseURL("https://fulcio.127.0.0.1.sslip.io:5555"), Trust: trust},
		Rekor:  endpoint.HTTPS{Address: endpoint.MustParseURL("https://rekor.127.0.0.1.sslip.io:3003"), Trust: trust},
		TSA:    endpoint.HTTPS{Address: endpoint.MustParseURL("https://tsa.127.0.0.1.sslip.io:3004"), Trust: trust},
	}

	// The token goes through the deploy's own read and pre-check, and the
	// producer checks the issued certificate against the identity and the
	// ref pin the harness issuer fills.
	ref := primitive.GitRef("refs/heads/main")
	liveOIDC := lane.OIDCConfig{
		Issuer:     endpoint.MustParseURL(liveIssuer),
		Identity:   liveIdentity,
		Extensions: lane.FulcioExtensions{SourceRepositoryRef: &ref},
		Token:      "builder-token",
	}
	d := &Deployer{
		OIDC: liveOIDC,
		Lane: &lane.Lane{Secrets: map[primitive.Identifier]lane.SecretSource{liveOIDC.Token: "env://SIGSTORE_ID_TOKEN"}},
	}
	token, err := d.builderToken()
	if err != nil {
		t.Fatalf("builderToken: %v", err)
	}

	statements := make([][]byte, 3)
	digests := make([]string, 3)
	for i := range statements {
		statements[i], digests[i] = liveStatement(i)
	}

	ctx := context.Background()
	bundles, err := ProduceKeylessBundles(ctx, eps, dialer, token, liveOIDC, statements)
	if err != nil {
		t.Fatalf("ProduceKeylessBundles: %v", err)
	}
	if len(bundles) != len(statements) {
		t.Fatalf("got %d bundles, want %d", len(bundles), len(statements))
	}

	fulcioClient, err := HTTPClientFor(eps.Fulcio, dialer)
	if err != nil {
		t.Fatalf("fulcio client: %v", err)
	}
	trustedRoot, err := testutil.HarnessTrustedRoot(ctx, fulcioClient, eps.Fulcio.Address.URL(), harness)
	if err != nil {
		t.Fatalf("harness trusted root: %v", err)
	}
	tr, err := root.NewTrustedRootFromJSON(trustedRoot)
	if err != nil {
		t.Fatalf("NewTrustedRootFromJSON: %v", err)
	}
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

	// The producer refuses a certificate that does not bind the declared
	// identity: Fulcio issues the harness identity, the declaration names
	// another, and no bundle is produced.
	foreign := lane.OIDCConfig{Issuer: endpoint.MustParseURL(liveIssuer), Identity: "https://forge.strike.localhost/istr/strike/other.cue@refs/heads/main"}
	if _, err := ProduceKeylessBundles(ctx, eps, dialer, token, foreign, statements); err == nil || !strings.Contains(err.Error(), "keyless: issued certificate:") {
		t.Fatalf("ProduceKeylessBundles under a foreign declared identity: err = %v, want an issued-certificate error", err)
	}
}
