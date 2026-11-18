package deploy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/record"
)

func TestProjectStatements(t *testing.T) {
	rootless := true
	preState := primitive.DigestFromHex(strings.Repeat("e", 64))
	postState := primitive.DigestFromHex(strings.Repeat("f", 64))
	att := &deploy.Attestation{
		Sealed: deploy.Sealed{
			LaneID:     "demo",
			LaneDigest: "",
			Artifacts: map[primitive.Identifier]record.Artifact{
				"b-image": {Digest: primitive.DigestFromHex(strings.Repeat("b", 64))},
				"a-image": {Digest: primitive.DigestFromHex(strings.Repeat("a", 64))},
			},
			Resolver: deploy.ResolverRecord{Host: "one.one.one.one:853", DialedIP: "1.1.1.1"},
			Peers:    map[primitive.Identifier][]endpoint.Endpoint{},
			Engine:   endpoint.EngineTLS{Type: "tls", CATrustType: "pinned", ServerCertFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		},
		EngineDependent: deploy.EngineDependent{
			PeerAttribution: map[primitive.Identifier][]endpoint.Authority{"build": {"git.example.com:22"}},
		},
		Informational: &deploy.Informational{
			Timestamp:       primitive.Timestamp(clock.Unix(0, 0).UTC().Format(clock.RFC3339)),
			EngineMetadata:  &deploy.EngineMetadata{Rootless: &rootless, Version: "5.3.1"},
			PreStateDigest:  preState,
			PostStateDigest: postState,
			Provenance:      []provenance.Record{},
		},
	}
	oidc := lane.OIDCConfig{Issuer: endpoint.MustParseURL("https://idp.example.com"), Identity: "deployer@example.com"}

	slsa, engineCtx, info, err := deploy.ProjectStatements(att, oidc, nil, "")
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

	// Sealed: declared OIDC identity carried; engine connection present.
	ep := slsa.Predicate.BuildDefinition.ExternalParameters
	if ep.OIDC.Issuer.URL() != "https://idp.example.com" || ep.OIDC.Identity != "deployer@example.com" {
		t.Error("OIDC identity not carried into sealed externalParameters")
	}
	if ep.Engine == nil {
		t.Error("engine connection (sealed layer) missing from sealed externalParameters")
	}

	// Engine-context (engine-dependent): engine-asserted peer attribution only.
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

	// A deploy that did not push lists no byproducts: its artifacts are the
	// subject. It states the version of strike all the same (ADR-060 D5).
	if run := slsa.Predicate.RunDetails; len(run.Byproducts) != 0 || run.Builder.Version.Strike != deploy.StrikeVersion {
		t.Errorf("runDetails = %+v, want no byproducts and the version of strike", run)
	}
}

// TestProjectStatementsPushed proves the sealed statement of a deploy that
// pushed (ADR-059 D1, ADR-060 D5). The subject is the pushed artifact. The
// resolved dependencies are the verified base statements and nothing else.
// The byproducts, sorted by name, are the produced identity of every artifact
// and every SBOM document under the name of its level: "/sbom/top-level" for
// the image arm, "/sbom" for a region. runDetails states the version of
// strike, and the statement holds against the contract.
func TestProjectStatementsPushed(t *testing.T) {
	const (
		producedImage = "1111111111111111111111111111111111111111111111111111111111111111"
		producedWeb   = "2222222222222222222222222222222222222222222222222222222222222222"
		producedNotes = "3333333333333333333333333333333333333333333333333333333333333333"
		pushed        = "4444444444444444444444444444444444444444444444444444444444444444"
		imageDocument = "5555555555555555555555555555555555555555555555555555555555555555"
		webDocument   = "6666666666666666666666666666666666666666666666666666666666666666"
		baseStatement = "7777777777777777777777777777777777777777777777777777777777777777"
		cycloneDX     = "application/vnd.cyclonedx+json"
	)
	att := &deploy.Attestation{
		Sealed: deploy.Sealed{
			LaneID:     "demo",
			LaneDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Artifacts: map[primitive.Identifier]record.Artifact{
				"web":   {Digest: "sha256:" + producedWeb, SBOM: &record.SBOMSet{CycloneDX: "sha256:" + webDocument}},
				"notes": {Digest: "sha256:" + producedNotes},
				"image": {Digest: "sha256:" + producedImage, SBOM: &record.SBOMSet{CycloneDX: "sha256:" + imageDocument}},
			},
			Pushed:   &deploy.PushedArtifact{Registry: "registry.example.com", Repository: "demo/app", Digest: "sha256:" + pushed},
			Resolver: deploy.ResolverRecord{Host: "one.one.one.one:853", DialedIP: "1.1.1.1"},
			Peers:    map[primitive.Identifier][]endpoint.Endpoint{},
		},
	}
	oidc := lane.OIDCConfig{Issuer: endpoint.MustParseURL("https://idp.example.com"), Identity: "deployer@example.com"}
	base := []deploy.ResourceDescriptor{{Name: "base", Digest: &deploy.DigestSet{SHA256: baseStatement}}}

	slsa, _, _, err := deploy.ProjectStatements(att, oidc, base, "image")
	if err != nil {
		t.Fatalf("ProjectStatements: %v", err)
	}

	if len(slsa.Subject) != 1 || slsa.Subject[0].Name != "demo/app" || slsa.Subject[0].Digest.SHA256 != pushed {
		t.Errorf("subject = %+v, want the pushed artifact demo/app", slsa.Subject)
	}
	deps := slsa.Predicate.BuildDefinition.ResolvedDependencies
	if len(deps) != 1 || deps[0].Name != "base" {
		t.Errorf("resolvedDependencies = %+v, want the one verified base statement and no produced identity", deps)
	}

	want := []struct {
		name      string
		mediaType string
		sha256    primitive.Sha256
	}{
		{name: "image", sha256: producedImage},
		{name: "image/sbom/top-level", mediaType: cycloneDX, sha256: imageDocument},
		{name: "notes", sha256: producedNotes},
		{name: "web", sha256: producedWeb},
		{name: "web/sbom", mediaType: cycloneDX, sha256: webDocument},
	}
	run := slsa.Predicate.RunDetails
	if len(run.Byproducts) != len(want) {
		t.Fatalf("byproducts = %+v, want %d entries", run.Byproducts, len(want))
	}
	for i, w := range want {
		got := run.Byproducts[i]
		if got.Name != w.name || got.MediaType != w.mediaType || got.Digest == nil || got.Digest.SHA256 != w.sha256 {
			t.Errorf("byproduct %d = name %q, media type %q, digest %+v, want %q, %q, %s", i, got.Name, got.MediaType, got.Digest, w.name, w.mediaType, w.sha256)
		}
		if got.URI != "" || got.DownloadLocation != "" {
			t.Errorf("byproduct %d carries a uri or a download location: %+v", i, got)
		}
	}
	if run.Builder.Version.Strike != deploy.StrikeVersion {
		t.Errorf("builder.version.strike = %q, want the version of strike, %q", run.Builder.Version.Strike, deploy.StrikeVersion)
	}

	data, err := json.Marshal(slsa)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	validateAgainstDef(t, data, "#SLSAProvenanceStatement")
}

// TestProjectStatementsPushedRejectsMalformedDigest proves that a produced
// identity or an SBOM document digest that is no sha256 digest fails the
// projection instead of reaching the sealed statement.
func TestProjectStatementsPushedRejectsMalformedDigest(t *testing.T) {
	const pushed = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	tests := []struct {
		name     string
		artifact record.Artifact
		wantErr  string
	}{
		{name: "produced identity", artifact: record.Artifact{Digest: "sha256:beef"}, wantErr: `byproduct "image": invalid digest`},
		{name: "document", artifact: record.Artifact{Digest: pushed, SBOM: &record.SBOMSet{CycloneDX: "md5:beef"}}, wantErr: `byproduct "image": sbom: invalid digest`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			att := &deploy.Attestation{Sealed: deploy.Sealed{
				Artifacts: map[primitive.Identifier]record.Artifact{"image": tt.artifact},
				Pushed:    &deploy.PushedArtifact{Registry: "registry.example.com", Repository: "demo/app", Digest: pushed},
			}}
			_, _, _, err := deploy.ProjectStatements(att, lane.OIDCConfig{}, nil, "image")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestStatementPayloadsFailsClosed proves that the payloads of a deploy are
// made from valid input only: a projection that fails and a document the
// canonical form refuses each fail the call, and no payload is returned.
func TestStatementPayloadsFailsClosed(t *testing.T) {
	const valid = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	tests := []struct {
		name    string
		pushed  primitive.Digest
		doc     string
		wantErr string
	}{
		{name: "malformed pushed digest", pushed: "sha256:beef", doc: `{}`, wantErr: "project statements: pushed subject"},
		{name: "number outside the canonical form", pushed: valid, doc: `{"n":1.5}`, wantErr: "marshal statement: canonical json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			att := &deploy.Attestation{Sealed: deploy.Sealed{
				Pushed: &deploy.PushedArtifact{Registry: "registry.example.com", Repository: "demo/app", Digest: tt.pushed},
			}}
			payloads, err := deploy.StatementPayloads(att, lane.OIDCConfig{}, nil, "image", []byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want an error containing %q", err, tt.wantErr)
			}
			if payloads != nil {
				t.Errorf("payloads = %d, want none beside an error", len(payloads))
			}
		})
	}
}
