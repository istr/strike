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
)

// fakeIDToken builds an unsigned JWT whose payload carries the given issuer
// claim. decodeIDTokenClaims does not verify tokens, so header and signature
// are placeholders.
func fakeIDToken(iss string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `"}`))
	return "e30." + payload + ".x"
}

// TestSignStatementsRejectsTokenBeforeFulcio proves the fail-closed pre-check:
// a real-path deploy (produceBundles == nil) whose ambient token is malformed
// or names an issuer other than the lane-declared one aborts before any
// keyless endpoint is contacted. Hermetic: the abort fires before the produce
// closure exists, so no network is touched.
func TestSignStatementsRejectsTokenBeforeFulcio(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{name: "foreign issuer", token: fakeIDToken("https://evil.example"), wantErr: "does not match the lane-declared issuer"},
		{name: "malformed token", token: "not-a-jwt", wantErr: "malformed identity token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGSTORE_ID_TOKEN", tt.token)
			d := &Deployer{
				OIDC: lane.OIDCConfig{
					Issuer:   endpoint.MustParseURL("https://idp.example.com"),
					Identity: "strike@example.com",
				},
			}
			att := &Attestation{
				Sealed: Sealed{
					LaneID:     "demo",
					LaneDigest: "",
					Artifacts: map[primitive.Identifier]record.Artifact{
						"b-image": {Digest: primitive.DigestFromHex(strings.Repeat("b", 64))},
					},
					Peers: map[primitive.Identifier][]lane.Peer{},
				},
			}
			_, err := d.signStatements(context.Background(), att, "deploy-step")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}
