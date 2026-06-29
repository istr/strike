package deploy

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/target"
)

// fakeIDToken builds an unsigned JWT whose payload carries the given email
// claim. subjectFromIDToken does not verify tokens, so header and signature
// are placeholders.
func fakeIDToken(email string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"` + email + `"}`))
	return "e30." + payload + ".x"
}

// TestSignStatementsRejectsMismatchedTokenIdentity proves the fail-closed
// declared-identity check: a real-path deploy (produceBundles == nil) whose
// ambient token subject differs from the lane-declared oidc identity aborts
// before any keyless endpoint is contacted. Hermetic: the mismatch fires
// before the produce closure exists, so no network is touched.
func TestSignStatementsRejectsMismatchedTokenIdentity(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", fakeIDToken("attacker@evil.example"))

	d := &Deployer{
		OIDC: lane.OIDCConfig{
			Issuer:   "https://idp.example.com",
			Identity: "strike@example.com",
		},
	}
	att := &Attestation{
		Sealed: Sealed{
			LaneID:     "demo",
			LaneDigest: "",
			Target:     target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
			Artifacts: map[string]record.Artifact{
				"b-image": {Digest: primitive.DigestFromHex(strings.Repeat("b", 64))},
			},
			Peers: map[primitive.Identifier][]lane.Peer{},
		},
	}

	err := d.signStatements(context.Background(), att, "deploy-step")
	if err == nil {
		t.Fatal("expected the mismatched token identity to abort signing")
	}
	if !strings.Contains(err.Error(), "does not match the lane-declared identity") {
		t.Fatalf("wrong error: %v", err)
	}
}
