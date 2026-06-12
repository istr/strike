package deploy_test

import (
	"encoding/json"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

func validateAgainstDef(t *testing.T, data []byte, def string) {
	t.Helper()
	ctx := cuecontext.New()
	compiled := ctx.CompileString(deploy.DeploySchema).LookupPath(cue.ParsePath(def))
	expr, err := cuejson.Extract("predicate.json", data)
	if err != nil {
		t.Fatalf("extract %s JSON: %v", def, err)
	}
	unified := compiled.Unify(ctx.BuildExpr(expr))
	if err := lane.FormatValidationError(unified.Validate(cue.Concrete(true))); err != nil {
		t.Fatalf("%s schema violation:\n%v", def, err)
	}
}

func TestSLSAProvenanceStatement_Valid(t *testing.T) {
	stmt := deploy.SLSAProvenanceStatement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []deploy.Subject{{Name: "image", Digest: deploy.DigestSet{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: deploy.SLSAProvenancePredicate{
			BuildDefinition: deploy.SLSABuildDefinition{
				BuildType: "https://istr.dev/strike/buildtypes/lane/v1",
				ExternalParameters: deploy.StrikeExternalParameters{
					LaneID:     "demo",
					LaneDigest: "",
					Target:     lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
					OIDC:       deploy.ProvenanceOIDC{Issuer: "https://idp.example.com", Identity: "strike@example.com"},
					Peers:      map[string][]lane.Peer{},
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
		Subject:       []deploy.Subject{{Name: "image", Digest: deploy.DigestSet{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}},
		PredicateType: "https://istr.dev/strike/predicates/informational/v1",
		Predicate: deploy.InformationalPredicate{
			Timestamp:       clock.Reproducible(),
			PreStateDigest:  lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			PostStateDigest: lane.MustParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			Provenance:      []lane.ProvenanceRecord{},
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
		Subject:       []deploy.Subject{{Name: "image", Digest: deploy.DigestSet{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}},
		PredicateType: "https://istr.dev/strike/predicates/engine-context/v1",
		Predicate: deploy.EngineContextPredicate{
			PeerAttribution: map[string][]string{"build": {"git.example.com:22"}},
		},
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	validateAgainstDef(t, data, "#EngineContextStatement")
}
