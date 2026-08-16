package lane

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/primitive"
)

// TestValidateDeployArtifactRefs pins the ADR-051 D9 structural rules over
// the deploy artifacts map: per-entry reference integrity for both arms,
// duplicate rejection, and the registry-method containment rules.
func TestValidateDeployArtifactRefs(t *testing.T) {
	out := primitive.Identifier("dist")
	miss := primitive.Identifier("missing")

	producer := &Step{ID: "web", Outputs: []FileOutput{{ID: "dist"}}}
	builder := &Step{ID: "build", Output: "image"}
	packer := &Step{ID: "pack", Output: "image", Pack: &PackSpec{
		Files: []PackFile{{From: OutputRef{Step: "web", Output: "dist"}}},
	}}
	registryDeploy := func(arts map[primitive.Identifier]ArtifactRef) *Step {
		return &Step{ID: "deploy", Deploy: &DeploySpec{
			Method:    DeployRegistry{Type: "registry"},
			Artifacts: arts,
		}}
	}
	kubeDeploy := func(arts map[primitive.Identifier]ArtifactRef) *Step {
		return &Step{ID: "deploy", Deploy: &DeploySpec{
			Method:    DeployKubernetes{Type: "kubernetes"},
			Artifacts: arts,
		}}
	}

	tests := []struct {
		name    string
		deploy  *Step
		wantErr string
	}{
		{
			name: "registry pack-covered region accepted",
			deploy: registryDeploy(map[primitive.Identifier]ArtifactRef{
				"app": {Step: "pack"},
				"web": {Step: "web", Output: &out},
			}),
		},
		{
			name:    "unknown step rejected",
			deploy:  kubeDeploy(map[primitive.Identifier]ArtifactRef{"x": {Step: "ghost"}}),
			wantErr: "references unknown step",
		},
		{
			name:    "image arm without image output rejected",
			deploy:  kubeDeploy(map[primitive.Identifier]ArtifactRef{"x": {Step: "web"}}),
			wantErr: "declares no image output",
		},
		{
			name:    "region output missing rejected",
			deploy:  kubeDeploy(map[primitive.Identifier]ArtifactRef{"x": {Step: "web", Output: &miss}}),
			wantErr: "not found in step",
		},
		{
			name: "duplicate output reference rejected",
			deploy: kubeDeploy(map[primitive.Identifier]ArtifactRef{
				"a": {Step: "web", Output: &out},
				"b": {Step: "web", Output: &out},
			}),
			wantErr: "reference the same output",
		},
		{
			name:    "registry empty map rejected",
			deploy:  registryDeploy(map[primitive.Identifier]ArtifactRef{}),
			wantErr: "non-empty artifacts map",
		},
		{
			name: "registry two image arms rejected",
			deploy: registryDeploy(map[primitive.Identifier]ArtifactRef{
				"a": {Step: "pack"},
				"b": {Step: "build"},
			}),
			wantErr: "exactly one image-arm",
		},
		{
			name: "registry region on build push rejected",
			deploy: registryDeploy(map[primitive.Identifier]ArtifactRef{
				"app": {Step: "build"},
				"web": {Step: "web", Output: &out},
			}),
			wantErr: "to be a pack step",
		},
		{
			name: "registry region not pack-covered rejected",
			deploy: func() *Step {
				bare := &Step{ID: "deploy", Deploy: &DeploySpec{
					Method: DeployRegistry{Type: "registry"},
					Artifacts: map[primitive.Identifier]ArtifactRef{
						"app": {Step: "barepack"},
						"web": {Step: "web", Output: &out},
					},
				}}
				return bare
			}(),
			wantErr: "is not packed into the pushed image",
		},
		{
			name: "kubernetes region entries pass entry integrity only",
			deploy: kubeDeploy(map[primitive.Identifier]ArtifactRef{
				"web": {Step: "web", Output: &out},
			}),
		},
	}

	barePack := &Step{ID: "barepack", Output: "image", Pack: &PackSpec{}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := map[primitive.Identifier]*Step{
				"web": producer, "build": builder, "pack": packer,
				"barepack": barePack, "deploy": tt.deploy,
			}
			p := &Lane{Steps: []Step{*producer, *builder, *packer, *barePack, *tt.deploy}}
			err := validateDeployArtifactRefs(p, index)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateDeployArtifactRefs: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
