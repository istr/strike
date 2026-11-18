package deploy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/schema"
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
					OIDC:       deploy.ProvenanceOIDC{Issuer: endpoint.MustParseURL("https://idp.example.com"), Identity: "strike@example.com"},
					Peers:      map[primitive.Identifier][]endpoint.Endpoint{},
					Resolver:   deploy.ResolverRecord{Host: "one.one.one.one:853", DialedIP: "1.1.1.1"},
				},
			},
			RunDetails: deploy.SLSARunDetails{Builder: deploy.SLSABuilder{ID: "https://istr.dev/strike", Version: deploy.SLSABuilderVersion{Strike: "1.2.3"}}},
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
			Timestamp:       primitive.Timestamp(clock.Unix(0, 0).UTC().Format(clock.RFC3339)),
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

// TestSLSABuilderVersion proves the grammar of builder.version (ADR-060 D2 and
// D5): the version is required, it is a closed struct with the one key
// "strike", and the value is a version by Semantic Versioning 2.0.0 without
// build metadata.
func TestSLSABuilderVersion(t *testing.T) {
	builder := func(version string) []byte {
		return []byte(`{"id":"https://istr.dev/strike","version":` + version + `}`)
	}
	for _, v := range []string{"1.2.3", "10.20.30", "1.0.0-rc.1", "1.0.0-0.3.7", "1.0.0-x.7.z.92", "1.0.0-alpha-beta", "0.1.0-0a"} {
		t.Run("valid "+v, func(t *testing.T) {
			validateAgainstDef(t, builder(`{"strike":"`+v+`"}`), "#SLSABuilder")
		})
	}
	for _, v := range []string{"", "1.2", "1.2.3.4", "01.2.3", "v1.2.3", "1.2.3+build", "1.2.3-rc.1+build.5", "1.2.3-", "1.2.3-01", "1.2.3-a..b"} {
		t.Run("invalid "+v, func(t *testing.T) {
			if err := schema.ValidateDef(schema.Deploy, "#SLSABuilder", builder(`{"strike":"`+v+`"}`)); err == nil {
				t.Errorf("version %q accepted, want a schema violation", v)
			}
		})
	}
	shapes := map[string][]byte{
		"no version":    []byte(`{"id":"https://istr.dev/strike"}`),
		"a bare string": builder(`"1.2.3"`),
		"no key":        builder(`{}`),
		"a second key":  builder(`{"strike":"1.2.3","commit":"0000000000000000000000000000000000000000"}`),
	}
	for shape, data := range shapes {
		t.Run(shape, func(t *testing.T) {
			if err := schema.ValidateDef(schema.Deploy, "#SLSABuilder", data); err == nil {
				t.Errorf("builder %s accepted, want a schema violation", data)
			}
		})
	}
}

// TestByproductName proves the name grammar of a byproduct (ADR-059 D1): the
// bare name of an artifacts entry, or that name followed by the level of an
// SBOM document. A byproduct without a name does not hold.
func TestByproductName(t *testing.T) {
	const digest = `"digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`
	runDetails := func(byproduct string) []byte {
		return []byte(`{"builder":{"id":"https://istr.dev/strike","version":{"strike":"1.2.3"}},"byproducts":[` + byproduct + `]}`)
	}
	for _, v := range []string{"image", "image/sbom", "image/sbom/top-level", "image/sbom/delivery-item"} {
		t.Run("valid "+v, func(t *testing.T) {
			validateAgainstDef(t, runDetails(`{"name":"`+v+`",`+digest+`}`), "#SLSARunDetails")
		})
	}
	for _, v := range []string{"", "Image", "image/", "image/spdx", "image/sbom/", "image/sbom/other", "image/sbom/top-level/x"} {
		t.Run("invalid "+v, func(t *testing.T) {
			if err := schema.ValidateDef(schema.Deploy, "#SLSARunDetails", runDetails(`{"name":"`+v+`",`+digest+`}`)); err == nil {
				t.Errorf("byproduct name %q accepted, want a schema violation", v)
			}
		})
	}
	t.Run("no name", func(t *testing.T) {
		if err := schema.ValidateDef(schema.Deploy, "#SLSARunDetails", runDetails(`{`+digest+`}`)); err == nil {
			t.Error("byproduct without a name accepted, want a schema violation")
		}
	})
}

// TestSBOMStatement proves what the contract fixes of the SBOM statement
// (ADR-059 D2): the statement type, at least one subject, the CycloneDX
// predicate type and, in the predicate, the format, the specification
// version, the document version and the form of the serial number. The rest
// of the document is left to the standard.
func TestSBOMStatement(t *testing.T) {
	const (
		subject  = `[{"name":"demo/app","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}]`
		cdxType  = "https://cyclonedx.org/bom"
		document = `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"serialNumber":"urn:uuid:01234567-89ab-4def-8123-456789abcdef","components":[]}`
	)
	statement := func(subj, predicateType, predicate string) []byte {
		return []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":` + subj + `,"predicateType":"` + predicateType + `","predicate":` + predicate + `}`)
	}
	validateAgainstDef(t, statement(subject, cdxType, document), "#SBOMStatement")

	invalid := map[string][]byte{
		"no subject":                    statement(`[]`, cdxType, document),
		"another predicate type":        statement(subject, "https://spdx.dev/Document", document),
		"another specification version": statement(subject, cdxType, strings.Replace(document, `"1.7"`, `"1.6"`, 1)),
		"another document version":      statement(subject, cdxType, strings.Replace(document, `"version":1`, `"version":2`, 1)),
		"no serial number":              statement(subject, cdxType, `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1}`),
		"a serial number in upper case": statement(subject, cdxType, strings.Replace(document, "89ab-4def", "89AB-4DEF", 1)),
	}
	for fault, data := range invalid {
		t.Run(fault, func(t *testing.T) {
			if err := schema.ValidateDef(schema.Deploy, "#SBOMStatement", data); err == nil {
				t.Errorf("statement %s accepted, want a schema violation", data)
			}
		})
	}
}
