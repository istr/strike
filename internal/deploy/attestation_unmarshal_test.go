package deploy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
)

// TestSealed_UnmarshalEngine exercises the engine dispatch in
// Sealed.UnmarshalJSON: a sealed record carrying an engine connection
// round-trips through the transport union decoder, and a malformed engine
// discriminator surfaces as a decode error rather than being silently dropped.
func TestSealed_UnmarshalEngine(t *testing.T) {
	orig := deploy.Sealed{
		LaneID:     "demo",
		LaneDigest: "",
		Artifacts:  map[primitive.Identifier]record.Artifact{},
		Peers:      map[primitive.Identifier][]lane.Peer{},
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
