package executor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// TestExecute_DigestGuard exercises the ADR-045 structural guard in
// Run.Execute: a step is refused before any engine call unless its image
// reference carries an @sha256: content digest. The guard covers both the
// Step.Image path and the image_from ImageRef override, so an execute-by-tag
// path cannot reappear. A digest-pinned reference passes the guard and reaches
// the later capsule check, proving the guard does not reject the valid form.
func TestExecute_DigestGuard(t *testing.T) {
	const digest = "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	tests := []struct {
		image       *primitive.ImageRef
		name        string
		imageRef    string
		wantErr     string
		wantNoGuard bool
	}{
		{
			name:    "mutable tag rejected",
			image:   lane.Ptr(primitive.ImageRef("alpine:latest")),
			wantErr: "ADR-045",
		},
		{
			name:    "empty image rejected",
			wantErr: "ADR-045",
		},
		{
			name:     "image_from tag override rejected",
			image:    lane.Ptr(primitive.ImageRef(digest)),
			imageRef: "localhost/strike/lane/step:spechash",
			wantErr:  "ADR-045",
		},
		{
			name:        "digest reference passes guard",
			image:       lane.Ptr(primitive.ImageRef(digest)),
			wantErr:     "capsule",
			wantNoGuard: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := executor.Run{
				Step:     &lane.Step{ID: "step", Image: tt.image, Args: []string{"true"}},
				ImageRef: tt.imageRef,
			}
			id, err := r.Execute(context.Background())
			if err == nil {
				t.Fatalf("Execute = nil error, want substring %q", tt.wantErr)
			}
			if id != "" {
				t.Errorf("id = %q, want empty on early return", id)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErr)
			}
			if tt.wantNoGuard && strings.Contains(err.Error(), "ADR-045") {
				t.Errorf("digest image tripped the ADR-045 guard: %v", err)
			}
		})
	}
}
