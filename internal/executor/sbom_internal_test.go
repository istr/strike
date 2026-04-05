package executor

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestFindSBOMDescriptor(t *testing.T) {
	tests := []struct {
		manifest *v1.IndexManifest
		name     string
		wantNil  bool
	}{
		{
			name: "cyclonedx+json match",
			manifest: &v1.IndexManifest{
				Manifests: []v1.Descriptor{
					{ArtifactType: "application/vnd.cyclonedx+json"},
				},
			},
			wantNil: false,
		},
		{
			name: "spdx match",
			manifest: &v1.IndexManifest{
				Manifests: []v1.Descriptor{
					{ArtifactType: "application/spdx+json"},
				},
			},
			wantNil: false,
		},
		{
			name: "syft match",
			manifest: &v1.IndexManifest{
				Manifests: []v1.Descriptor{
					{ArtifactType: "application/vnd.syft+json"},
				},
			},
			wantNil: false,
		},
		{
			name: "no match",
			manifest: &v1.IndexManifest{
				Manifests: []v1.Descriptor{
					{ArtifactType: "application/octet-stream"},
				},
			},
			wantNil: true,
		},
		{
			name: "empty manifests",
			manifest: &v1.IndexManifest{
				Manifests: []v1.Descriptor{},
			},
			wantNil: true,
		},
		{
			name: "match among multiple",
			manifest: &v1.IndexManifest{
				Manifests: []v1.Descriptor{
					{ArtifactType: "application/octet-stream"},
					{ArtifactType: "application/vnd.syft+json"},
					{ArtifactType: "text/plain"},
				},
			},
			wantNil: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findSBOMDescriptor(tt.manifest)
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %v", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("expected non-nil descriptor")
			}
		})
	}
}
