package deploy_test

import (
	"encoding/json"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/schema"
	"github.com/istr/strike/internal/target"
)

func validateAgainstDef(t *testing.T, data []byte, def string) {
	t.Helper()
	if err := schema.ValidateDef(schema.Deploy, def, data); err != nil {
		t.Fatalf("%s schema violation:\n%v", def, err)
	}
}

func TestSLSAProvenanceStatement_Valid(t *testing.T) {
	stmt := deploy.SLSAProvenanceStatement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []deploy.Subject{{Name: "image", Digest: &deploy.DigestSet{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: deploy.SLSAProvenancePredicate{
			BuildDefinition: deploy.SLSABuildDefinition{
				BuildType: "https://istr.dev/strike/buildtypes/lane/v1",
				ExternalParameters: deploy.StrikeExternalParameters{
					LaneID:     "demo",
					LaneDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					Target:     target.Deploy{ID: "prod-1", Type: "registry", Description: "production"},
					OIDC:       deploy.ProvenanceOIDC{Issuer: "https://idp.example.com", Identity: "strike@example.com"},
					Peers:      map[primitive.Identifier][]lane.Peer{},
				},
			},
			RunDetails: deploy.SLSARunDetails{Builder: deploy.SLSABuilder{ID: "https://istr.dev/strike"}},
		},
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	validateAgainstDef(t, data, "#SLSAProvenanceStatement")
}

func TestInformationalStatement_Valid(t *testing.T) {
	stmt := deploy.InformationalStatement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []deploy.Subject{{Name: "image", Digest: &deploy.DigestSet{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}},
		PredicateType: "https://istr.dev/strike/predicates/informational/v1",
		Predicate: deploy.InformationalPredicate{
			Timestamp:       primitive.Timestamp(clock.Reproducible().Format(clock.RFC3339)),
			PreStateDigest:  primitive.DigestFromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			PostStateDigest: primitive.DigestFromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			Provenance:      []provenance.Record{},
		},
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	validateAgainstDef(t, data, "#InformationalStatement")
}

func TestEngineContextStatement_Valid(t *testing.T) {
	stmt := deploy.EngineContextStatement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []deploy.Subject{{Name: "image", Digest: &deploy.DigestSet{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}},
		PredicateType: "https://istr.dev/strike/predicates/engine-context/v1",
		Predicate: deploy.EngineContextPredicate{
			PeerAttribution: map[primitive.Identifier][]endpoint.Authority{"build": {"git.example.com:22"}},
		},
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	validateAgainstDef(t, data, "#EngineContextStatement")
}
