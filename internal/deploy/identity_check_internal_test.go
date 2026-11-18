package deploy

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry"
)

// fakeIDToken builds an unsigned JWT whose payload is the given claims JSON.
// decodeIDTokenClaims does not verify tokens, so header and signature are
// placeholders.
func fakeIDToken(claims string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".x"
}

// TestSignStatementsRejectsTokenBeforeFulcio proves the fail-closed pre-check:
// a real-path deploy (produceBundles == nil) whose builder token cannot be
// read, is malformed, names an issuer other than the lane-declared one, or
// lives longer than the bound aborts before any keyless endpoint is
// contacted. Hermetic: the abort fires before the produce closure exists, so
// no network is touched.
func TestSignStatementsRejectsTokenBeforeFulcio(t *testing.T) {
	tests := []struct {
		name    string
		source  lane.SecretSource
		token   string
		wantErr string
	}{
		{name: "unset variable", source: "env://STRIKE_TEST_UNSET_BUILDER_TOKEN", wantErr: "oidc token \"builder-token\""},
		{name: "malformed token", source: "env://SIGSTORE_ID_TOKEN", token: "not-a-jwt", wantErr: "malformed identity token"},
		{name: "foreign issuer", source: "env://SIGSTORE_ID_TOKEN", token: fakeIDToken(`{"iss":"https://evil.example","iat":1000,"exp":1600}`), wantErr: "does not match the lane-declared issuer"},
		{name: "no lifetime", source: "env://SIGSTORE_ID_TOKEN", token: fakeIDToken(`{"iss":"https://idp.example.com"}`), wantErr: "no valid iat and exp"},
		{name: "lifetime over bound", source: "env://SIGSTORE_ID_TOKEN", token: fakeIDToken(`{"iss":"https://idp.example.com","iat":1000,"exp":1901}`), wantErr: "exceeds the 900s bound"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGSTORE_ID_TOKEN", tt.token)
			d := &Deployer{
				OIDC: lane.OIDCConfig{
					Issuer:   endpoint.MustParseURL("https://idp.example.com"),
					Identity: "strike@example.com",
					Token:    "builder-token",
				},
				Lane: &lane.Lane{Secrets: map[primitive.Identifier]lane.SecretSource{"builder-token": tt.source}},
			}
			att := &Attestation{
				Sealed: Sealed{
					LaneID:     "demo",
					LaneDigest: "",
					Artifacts: map[primitive.Identifier]record.Artifact{
						"b-image": {Digest: primitive.DigestFromHex(strings.Repeat("b", 64))},
					},
					Peers: map[primitive.Identifier][]endpoint.Endpoint{},
				},
			}
			_, err := d.signStatements(context.Background(), att, "deploy-step", nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestSignStatementsRefusesOversizedStatement proves the bound a deploy
// applies before it signs (ADR-059 D2): a statement of exactly
// registry.MaxStatementBytes is signed, and a statement one byte larger fails
// the deploy before a bundle is produced. The document decides the size of
// the SBOM statement, so the document is what grows here.
func TestSignStatementsRefusesOversizedStatement(t *testing.T) {
	att := &Attestation{
		Sealed: Sealed{
			LaneID: "demo",
			Artifacts: map[primitive.Identifier]record.Artifact{
				"image": {Digest: primitive.DigestFromHex(strings.Repeat("b", 64))},
			},
			Pushed: &PushedArtifact{Registry: "registry.example.com", Repository: "demo/app", Digest: primitive.DigestFromHex(strings.Repeat("c", 64))},
			Peers:  map[primitive.Identifier][]endpoint.Endpoint{},
		},
	}
	document := func(n int) []byte {
		return []byte(`{"pad":"` + strings.Repeat("a", n) + `"}`)
	}
	smallest, err := StatementPayloads(att, lane.OIDCConfig{}, nil, "image", document(0))
	if err != nil {
		t.Fatalf("StatementPayloads: %v", err)
	}
	if len(smallest) != 4 {
		t.Fatalf("statements = %d, want 4", len(smallest))
	}
	pad := registry.MaxStatementBytes - len(smallest[3])

	var produced [][]byte
	d := &Deployer{}
	d.produceBundles = func(_ context.Context, _ lane.KeylessEndpoints, statements [][]byte) ([][]byte, error) {
		produced = statements
		return make([][]byte, len(statements)), nil
	}

	if _, signErr := d.signStatements(context.Background(), att, "deploy-step", &attachTarget{image: "image", document: document(pad)}); signErr != nil {
		t.Fatalf("a statement of exactly %d bytes was refused: %v", registry.MaxStatementBytes, signErr)
	}
	if len(produced) != 4 || len(produced[3]) != registry.MaxStatementBytes {
		t.Fatalf("produced %d statements, want 4 with an SBOM statement of %d bytes", len(produced), registry.MaxStatementBytes)
	}

	produced = nil
	_, err = d.signStatements(context.Background(), att, "deploy-step", &attachTarget{image: "image", document: document(pad + 1)})
	if err == nil || !strings.Contains(err.Error(), "the SBOM statement has") {
		t.Fatalf("err = %v, want an error naming the SBOM statement", err)
	}
	if produced != nil {
		t.Error("a bundle was produced for a deploy that signs an oversized statement")
	}
}
