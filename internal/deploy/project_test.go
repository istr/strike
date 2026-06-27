package deploy_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

func TestProjectStatements(t *testing.T) {
	rootless := true
	preState := primitive.Digest("sha256:" + strings.Repeat("e", 64))
	postState := primitive.Digest("sha256:" + strings.Repeat("f", 64))
	att := &deploy.Attestation{
		Sealed: deploy.Sealed{
			LaneID:     "demo",
			LaneDigest: "",
			Target:     lane.DeployTarget{ID: "prod-1", Type: "registry", Description: "production"},
			Artifacts: map[string]deploy.ArtifactRecord{
				"b-image": {Digest: primitive.Digest("sha256:" + strings.Repeat("b", 64))},
				"a-image": {Digest: primitive.Digest("sha256:" + strings.Repeat("a", 64))},
			},
			Peers:  map[string][]lane.Peer{},
			Engine: endpoint.EngineTLS{Type: "tls", CATrustType: "pinned", ServerCertFingerprint: "sha256:cc"},
		},
		EngineDependent: deploy.EngineDependent{
			PeerAttribution: map[string][]string{"build": {"git.example.com:22"}},
		},
		Informational: &deploy.Informational{
			Timestamp:       clock.Reproducible(),
			EngineMetadata:  &deploy.EngineMetadata{Rootless: &rootless, Version: "5.3.1"},
			PreStateDigest:  lane.MustParseDigest(preState).Wire(),
			PostStateDigest: lane.MustParseDigest(postState).Wire(),
			Provenance:      []lane.ProvenanceRecord{},
		},
	}
	oidc := lane.OIDCConfig{Issuer: "https://idp.example.com", Identity: "deployer@example.com"}

	slsa, engineCtx, info, err := deploy.ProjectStatements(att, oidc, nil)
	if err != nil {
		t.Fatalf("projectStatements: %v", err)
	}

	// Subject is shared and sorted by name across all three statements.
	if len(slsa.Subject) != 2 || slsa.Subject[0].Name != "a-image" || slsa.Subject[1].Name != "b-image" {
		t.Fatalf("subject not sorted: %+v", slsa.Subject)
	}
	if slsa.Subject[0].Digest.SHA256 != primitive.Sha256(strings.Repeat("a", 64)) {
		t.Errorf("subject digest = %q", slsa.Subject[0].Digest.SHA256)
	}

	// Sealed (V): declared OIDC identity carried; engine connection present.
	ep := slsa.Predicate.BuildDefinition.ExternalParameters
	if ep.OIDC.Issuer != "https://idp.example.com" || ep.OIDC.Identity != "deployer@example.com" {
		t.Error("OIDC identity not carried into sealed externalParameters")
	}
	if ep.Engine == nil {
		t.Error("engine connection (Layer V) missing from sealed externalParameters")
	}

	// Engine-context (E): engine-asserted peer attribution only.
	if len(engineCtx.Predicate.PeerAttribution) != 1 {
		t.Error("peer attribution missing from engine-context")
	}

	// Informational: engine self-report, state digests, and provenance here.
	if info.Predicate.EngineMetadata == nil || info.Predicate.EngineMetadata.Version != "5.3.1" {
		t.Error("engine metadata not classified as informational")
	}
	if info.Predicate.PreStateDigest != preState {
		t.Errorf("pre-state digest = %q", info.Predicate.PreStateDigest)
	}
	if info.PredicateType != "https://istr.dev/strike/predicates/informational/v1" {
		t.Errorf("informational predicateType = %q", info.PredicateType)
	}
}
