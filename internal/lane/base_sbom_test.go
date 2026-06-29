package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

func digestRef(tag string) primitive.ImageRef {
	return primitive.ImageRef(tag + "@sha256:" + strings.Repeat("a", 64))
}

func TestPackBaseRefs_CollectsSubtreeBases(t *testing.T) {
	base := digestRef("base")
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "compile", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "binary", Type: "file", Path: primitive.RelPathPtr("binary")}},
			},
			{
				ID: "pack", Args: []string{}, Env: map[string]string{},
				Pack: &lane.PackSpec{
					Base:  base,
					Files: []lane.PackFile{{From: lane.OutputRef{Step: "compile", Output: "binary"}, Dest: "/app", Mode: 0o755}},
				},
				Output: "image",
			},
			{
				ID: "deploy", Args: []string{}, Env: map[string]string{},
				Deploy: &lane.DeploySpec{
					Artifacts: map[string]lane.ArtifactRef{"image": {From: lane.StepImageRef{Step: "pack"}}},
				},
			},
		},
	}
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	got := dag.PackBaseRefs("deploy")
	if len(got) != 1 || got[0] != base {
		t.Fatalf("PackBaseRefs(deploy) = %v, want [%s]", got, base)
	}
	// The deploy step itself is excluded; a leaf pack with no downstream yields
	// its base only when reached as a predecessor, confirmed above.
}

func TestValidateBaseSBOMTrustAnchor_RequiresTrustRoot(t *testing.T) {
	mkLane := func(k lane.Keyless) *lane.Lane {
		return &lane.Lane{
			Keyless:         k,
			BaseSBOMSigners: []lane.SBOMSigner{{Issuer: "https://issuer.example", Identity: "signer@example"}},
			Steps: []lane.Step{
				{
					ID: "run", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
					Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("out")}},
				},
			},
		}
	}

	// No trust root: build must fail.
	if _, err := lane.Build(mkLane(lane.Keyless{})); err == nil {
		t.Fatal("expected build error: baseSbomSigners without a trust root")
	} else if !strings.Contains(err.Error(), "baseSbomSigners") {
		t.Errorf("error should mention baseSbomSigners: %v", err)
	}

	// trustRootRef present: the anchor is satisfied, build passes.
	if _, err := lane.Build(mkLane(lane.Keyless{TrustRootRef: digestRef("tr")})); err != nil {
		t.Fatalf("build should pass with a trust root ref: %v", err)
	}
}

func TestValidateBaseSBOMTrustAnchor_NoSignersNoConstraint(t *testing.T) {
	// A lane with no base SBOM signers needs no trust root.
	p := &lane.Lane{
		Steps: []lane.Step{
			{
				ID: "run", Image: primitive.ImageRefPtr("img"), Args: []string{}, Env: map[string]string{},
				Outputs: []lane.FileOutput{{ID: "out", Type: "file", Path: primitive.RelPathPtr("out")}},
			},
		},
	}
	if _, err := lane.Build(p); err != nil {
		t.Fatalf("build should pass with no base SBOM signers: %v", err)
	}
}
