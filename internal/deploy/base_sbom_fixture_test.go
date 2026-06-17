package deploy_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/istr/strike/internal/verify"
)

// fixtureMeta mirrors internal/deploy/testdata/base-sbom/meta.json.
type fixtureMeta struct {
	SubjectDigest          string `json:"subjectDigest"`
	Identity               string `json:"identity"`
	Issuer                 string `json:"issuer"`
	CycloneDXPredicateType string `json:"cyclonedxPredicateType"`
	SPDXPredicateType      string `json:"spdxPredicateType"`
}

func readFixtureMeta(t *testing.T) fixtureMeta {
	t.Helper()
	b, err := os.ReadFile("testdata/base-sbom/meta.json")
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var m fixtureMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	return m
}

// TestBaseSBOMFixtureVerifiesUnderStrike confirms strike's own verify.Verify
// accepts the recorded cosign attest CycloneDX bundle end to end and that the
// signed payload binds to the recorded base digest. This is the empirical
// "verify.Verify: GO" confirmation the 2c spike inferred but did not run.
func TestBaseSBOMFixtureVerifiesUnderStrike(t *testing.T) {
	meta := readFixtureMeta(t)
	tr, err := os.ReadFile("testdata/base-sbom/trusted_root.json")
	if err != nil {
		t.Fatalf("read trusted root: %v", err)
	}
	tm, err := verify.ParseTrustedRoot(tr)
	if err != nil {
		t.Fatalf("parse trusted root: %v", err)
	}
	bundle, err := os.ReadFile("testdata/base-sbom/cyclonedx.bundle.json")
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	payload, err := verify.New(tm, meta.Identity, meta.Issuer).Verify(bundle)
	if err != nil {
		t.Fatalf("strike verify rejected the cosign CycloneDX bundle: %v", err)
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest struct {
				SHA256 string `json:"sha256"`
			} `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("parse verified payload: %v", err)
	}
	if stmt.PredicateType != meta.CycloneDXPredicateType {
		t.Errorf("payload predicateType = %q, want %q", stmt.PredicateType, meta.CycloneDXPredicateType)
	}
	if len(stmt.Subject) == 0 {
		t.Fatal("verified payload has no subject")
	}
	if got := "sha256:" + stmt.Subject[0].Digest.SHA256; got != meta.SubjectDigest {
		t.Errorf("payload subject digest = %q, want %q (base binding)", got, meta.SubjectDigest)
	}
}
