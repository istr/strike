package deploy

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/verify"
)

type baseSBOMMeta struct {
	SubjectDigest          string `json:"subjectDigest"`
	Identity               string `json:"identity"`
	Issuer                 string `json:"issuer"`
	CycloneDXPredicateType string `json:"cyclonedxPredicateType"`
}

func loadBaseSBOMFixture(t *testing.T) (*verify.TrustedMaterial, baseSBOMMeta, []byte) {
	t.Helper()
	mb, err := os.ReadFile("testdata/base-sbom/meta.json")
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var m baseSBOMMeta
	if err = json.Unmarshal(mb, &m); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
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
	return tm, m, bundle
}

func TestVerifyOneBaseSBOM_HappyPath(t *testing.T) {
	tm, m, bundle := loadBaseSBOMFixture(t)
	d := &Deployer{BaseSBOMSigners: []lane.SBOMSigner{{Issuer: m.Issuer, Identity: m.Identity}}}
	base := primitive.ImageRef("localhost/strike-base@" + m.SubjectDigest)
	baseHex := primitive.Sha256(strings.TrimPrefix(m.SubjectDigest, "sha256:"))
	refDigest := "sha256:" + strings.Repeat("b", 64)

	dep, recorded, err := d.verifyOneBaseSBOM(tm, base, baseHex, registry.BaseSBOMReferrer{
		Digest:        refDigest,
		PredicateType: m.CycloneDXPredicateType,
		Bundle:        bundle,
	})
	if err != nil {
		t.Fatalf("verifyOneBaseSBOM: %v", err)
	}
	if !recorded {
		t.Fatal("expected the verified base SBOM to be recorded")
	}
	if dep.MediaType != m.CycloneDXPredicateType {
		t.Errorf("MediaType = %q, want %q", dep.MediaType, m.CycloneDXPredicateType)
	}
	if dep.Digest == nil || dep.Digest.SHA256 != primitive.Sha256(strings.TrimPrefix(refDigest, "sha256:")) {
		t.Errorf("descriptor digest = %v, want referrer digest", dep.Digest)
	}
	if dep.URI != string(base) {
		t.Errorf("URI = %q, want %q", dep.URI, base)
	}
}

func TestVerifyOneBaseSBOM_SubjectMismatchFails(t *testing.T) {
	tm, m, bundle := loadBaseSBOMFixture(t)
	d := &Deployer{BaseSBOMSigners: []lane.SBOMSigner{{Issuer: m.Issuer, Identity: m.Identity}}}
	base := primitive.ImageRef("localhost/strike-base@sha256:" + strings.Repeat("c", 64))
	wrongHex := primitive.Sha256(strings.Repeat("c", 64))

	_, recorded, err := d.verifyOneBaseSBOM(tm, base, wrongHex, registry.BaseSBOMReferrer{
		Digest:        "sha256:" + strings.Repeat("b", 64),
		PredicateType: m.CycloneDXPredicateType,
		Bundle:        bundle,
	})
	if err == nil {
		t.Fatal("expected fail-closed error on subject mismatch")
	}
	if recorded {
		t.Fatal("must not record on subject mismatch")
	}
}

func TestVerifyOneBaseSBOM_WrongSignerFails(t *testing.T) {
	tm, m, bundle := loadBaseSBOMFixture(t)
	d := &Deployer{BaseSBOMSigners: []lane.SBOMSigner{{Issuer: "https://wrong.example", Identity: "wrong@example"}}}
	base := primitive.ImageRef("localhost/strike-base@" + m.SubjectDigest)
	baseHex := primitive.Sha256(strings.TrimPrefix(m.SubjectDigest, "sha256:"))

	_, recorded, err := d.verifyOneBaseSBOM(tm, base, baseHex, registry.BaseSBOMReferrer{
		Digest:        "sha256:" + strings.Repeat("b", 64),
		PredicateType: m.CycloneDXPredicateType,
		Bundle:        bundle,
	})
	if err == nil {
		t.Fatal("expected fail-closed error when no declared signer verifies")
	}
	if recorded {
		t.Fatal("must not record when no signer verifies")
	}
}

func TestVerifyBaseSBOMs_NoSignersIsNoop(t *testing.T) {
	d := &Deployer{}
	deps, err := d.verifyBaseSBOMs(context.Background(), "deploy")
	if err != nil {
		t.Fatalf("verifyBaseSBOMs: %v", err)
	}
	if deps != nil {
		t.Errorf("deps = %v, want nil for a lane with no base SBOM signers", deps)
	}
}

func TestVerifyBaseSBOMs_SignersWithoutTrustRootFails(t *testing.T) {
	d := &Deployer{BaseSBOMSigners: []lane.SBOMSigner{{Issuer: "https://issuer.example", Identity: "signer@example"}}}
	_, err := d.verifyBaseSBOMs(context.Background(), "deploy")
	if err == nil {
		t.Fatal("expected fail-closed error when signers are declared but no trust root resolves")
	}
}
