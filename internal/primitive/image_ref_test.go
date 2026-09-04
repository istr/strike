package primitive_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/primitive"
)

func TestImageRefDigest(t *testing.T) {
	const hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	tests := []struct {
		name    string
		in      string
		want    primitive.Digest
		wantErr string
	}{
		{
			name: "digest pinned",
			in:   "docker.io/lib/img@sha256:" + hex,
			want: primitive.Digest("sha256:" + hex),
		},
		{
			name: "splits at the last at sign",
			in:   "reg@example/lib/img@sha256:" + hex,
			want: primitive.Digest("sha256:" + hex),
		},
		{
			name: "no digest is absence, not an error",
			in:   "myimage:latest",
		},
		{
			name:    "empty body",
			in:      "myimage@",
			wantErr: "empty digest",
		},
		{
			name:    "malformed body",
			in:      "myimage@sha512:" + hex,
			wantErr: "must start with",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := primitive.NewImageRef(tt.in).Digest()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Digest() error = nil, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Digest() error = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Digest() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("Digest() = %q, want %q", got, tt.want)
			}
		})
	}
}
