package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestParseDigest_Valid(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{
			name: "empty returns zero digest",
			in:   "",
		},
		{
			name: "canonical 64 hex zeros",
			in:   "sha256:" + strings.Repeat("0", 64),
		},
		{
			name: "canonical 64 hex mixed",
			in:   "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name: "sha256 of empty input",
			in:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := lane.ParseDigest(tt.in)
			if err != nil {
				t.Fatalf("ParseDigest(%q) returned error: %v", tt.in, err)
			}
			if tt.in == "" {
				if !d.IsZero() {
					t.Errorf("empty input should yield zero digest, got %+v", d)
				}
				return
			}
			if d.String() != tt.in {
				t.Errorf("round-trip: got %q, want %q", d.String(), tt.in)
			}
		})
	}
}

func TestParseDigest_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantErrPart string
	}{
		{
			name:        "no colon",
			in:          "sha256",
			wantErrPart: "expected algorithm:hex",
		},
		{
			name:        "colon at start",
			in:          ":abcdef",
			wantErrPart: "expected algorithm:hex",
		},
		{
			name:        "wrong algorithm md5",
			in:          "md5:" + strings.Repeat("0", 32),
			wantErrPart: "algorithm must be",
		},
		{
			name:        "wrong algorithm sha512",
			in:          "sha512:" + strings.Repeat("0", 64),
			wantErrPart: "algorithm must be",
		},
		{
			name:        "empty hex",
			in:          "sha256:",
			wantErrPart: "hex must be 64 chars",
		},
		{
			name:        "hex too short",
			in:          "sha256:abc",
			wantErrPart: "hex must be 64 chars",
		},
		{
			name:        "hex too long",
			in:          "sha256:" + strings.Repeat("a", 65),
			wantErrPart: "hex must be 64 chars",
		},
		{
			name:        "hex uppercase",
			in:          "sha256:" + strings.Repeat("A", 64),
			wantErrPart: "lowercase",
		},
		{
			name:        "hex non-hex character",
			in:          "sha256:" + strings.Repeat("a", 63) + "z",
			wantErrPart: "lowercase",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lane.ParseDigest(tt.in)
			if err == nil {
				t.Fatalf("ParseDigest(%q) succeeded, want error containing %q",
					tt.in, tt.wantErrPart)
			}
			if !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrPart)
			}
		})
	}
}

func TestMustParseDigest_PanicsOnInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = lane.MustParseDigest("sha256:abc")
}
