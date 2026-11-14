package deploy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/testutil"
)

// TestStrikeExternalParameters_Unmarshal exercises the union dispatch on the
// sealed statement's externalParameters: a declared peer and an engine
// connection round-trip through their union decoders, and a malformed engine
// discriminator or a malformed document surfaces as a decode error.
func TestStrikeExternalParameters_Unmarshal(t *testing.T) {
	orig := deploy.StrikeExternalParameters{
		LaneID: "demo",
		OIDC:   deploy.ProvenanceOIDC{Issuer: endpoint.MustParseURL("https://idp.example.com"), Identity: "deployer@example.com"},
		Peers: map[primitive.Identifier][]endpoint.Endpoint{
			"build": {endpoint.TLS{Type: "https", Address: endpoint.MustParseAuthority("localhost:5555"), Trust: testutil.AnchorTrust()}},
		},
		Engine: endpoint.EngineUnix{Type: "unix"},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got deploy.StrikeExternalParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got.Engine.(endpoint.EngineUnix); !ok {
		t.Errorf("Engine type = %T, want endpoint.EngineUnix", got.Engine)
	}
	if peers := got.Peers["build"]; len(peers) != 1 {
		t.Errorf("peers[build] = %v, want one peer", peers)
	} else if _, ok := peers[0].(endpoint.TLS); !ok {
		t.Errorf("peer type = %T, want endpoint.TLS", peers[0])
	}

	for _, tc := range []struct{ in, want string }{
		{`{"engine": {"type": "bogus"}}`, "externalParameters engine"},
		{`{"peers": 5}`, "cannot unmarshal"},
	} {
		var p deploy.StrikeExternalParameters
		if err := json.Unmarshal([]byte(tc.in), &p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want substring %q", tc.in, err, tc.want)
		}
	}
}

// TestSealed_UnmarshalEngine exercises the engine dispatch in
// Sealed.UnmarshalJSON: a sealed record carrying an engine connection
// round-trips through the transport union decoder, and a malformed engine
// discriminator surfaces as a decode error rather than being silently dropped.
func TestSealed_UnmarshalEngine(t *testing.T) {
	orig := deploy.Sealed{
		LaneID:     "demo",
		LaneDigest: "",
		Artifacts:  map[primitive.Identifier]record.Artifact{},
		Peers:      map[primitive.Identifier][]endpoint.Endpoint{},
		Engine: endpoint.EngineMTLS{
			Type:                  "mtls",
			CATrustType:           "pinned",
			ServerCertFingerprint: "sha256:aa",
			ClientCertFingerprint: "sha256:bb",
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got deploy.Sealed
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m, ok := got.Engine.(endpoint.EngineMTLS)
	if !ok {
		t.Fatalf("Engine type = %T, want endpoint.EngineMTLS", got.Engine)
	}
	if m.ClientCertFingerprint != "sha256:bb" {
		t.Errorf("ClientCertFingerprint = %q, want sha256:bb", m.ClientCertFingerprint)
	}

	// A malformed engine discriminator is surfaced, not silently dropped.
	const bad = `{"peers": {}, "engine": {"type": "bogus"}}`
	var s deploy.Sealed
	if err := json.Unmarshal([]byte(bad), &s); err == nil {
		t.Fatal("expected error for unknown engine type")
	} else if !strings.Contains(err.Error(), "attestation engine") {
		t.Errorf("error = %v, want substring \"attestation engine\"", err)
	}
}
