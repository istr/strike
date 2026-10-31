package deploy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestProvenanceOIDCWireNeutral pins the sealed provenance oidc block to the
// bytes the golden sealed statement was signed over: the block decoded into
// ProvenanceOIDC and re-encoded on the signing path's canonical form equals
// the same block decoded generically and re-encoded the same way.
func TestProvenanceOIDCWireNeutral(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(filepath.Join("..", "verify", "testdata", "golden", "sealed.sigstore.json")))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var b struct {
		DSSEEnvelope struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err = json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse golden bundle: %v", err)
	}
	var stmt struct {
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters struct {
					OIDC json.RawMessage `json:"oidc"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err = json.Unmarshal(b.DSSEEnvelope.Payload, &stmt); err != nil {
		t.Fatalf("parse golden statement: %v", err)
	}
	block := stmt.Predicate.BuildDefinition.ExternalParameters.OIDC
	if len(block) == 0 {
		t.Fatal("golden statement carries no oidc block")
	}
	var generic any
	if err = json.Unmarshal(block, &generic); err != nil {
		t.Fatalf("decode oidc block generically: %v", err)
	}
	want, err := canonicalJSON(generic)
	if err != nil {
		t.Fatalf("canonical generic: %v", err)
	}
	var typed ProvenanceOIDC
	if err = json.Unmarshal(block, &typed); err != nil {
		t.Fatalf("decode oidc block as ProvenanceOIDC: %v", err)
	}
	got, err := canonicalJSON(typed)
	if err != nil {
		t.Fatalf("canonical typed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("typed oidc block = %s, signed bytes = %s", got, want)
	}
}
