package primitive_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/primitive"
)

func TestParseDigest_Valid(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{
			name: "empty returns empty digest",
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
			d, err := primitive.ParseDigest(primitive.Digest(tt.in))
			if err != nil {
				t.Fatalf("ParseDigest(%q) returned error: %v", tt.in, err)
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
			name:        "no prefix",
			in:          "sha256",
			wantErrPart: "must start with",
		},
		{
			name:        "wrong algorithm md5",
			in:          "md5:" + strings.Repeat("0", 32),
			wantErrPart: "must start with",
		},
		{
			name:        "wrong algorithm sha512",
			in:          "sha512:" + strings.Repeat("0", 64),
			wantErrPart: "must start with",
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
			_, err := primitive.ParseDigest(primitive.Digest(tt.in))
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

func TestDigestHex(t *testing.T) {
	const hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := primitive.Digest("sha256:" + hex).Hex(); got != primitive.Sha256(hex) {
		t.Errorf("Hex() = %q, want %q", got, hex)
	}
	if got := primitive.Digest("").Hex(); got != "" {
		t.Errorf("Hex() of empty digest = %q, want empty", got)
	}
}

// TestDigestFromHex is symmetric to TestDigestHex: DigestFromHex prepends the
// fixed "sha256:" prefix and performs no validation (an empty body yields the
// bare prefix, not the empty digest).
func TestDigestFromHex(t *testing.T) {
	const hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := primitive.DigestFromHex(hex); got != primitive.Digest("sha256:"+hex) {
		t.Errorf("DigestFromHex(%q) = %q, want sha256:%s", hex, got, hex)
	}
	if got := primitive.DigestFromHex(""); got != "sha256:" {
		t.Errorf("DigestFromHex(\"\") = %q, want \"sha256:\"", got)
	}
}

// TestDigestHexFromHexRoundTrip pins DigestFromHex and Hex as inverses on a
// canonical digest: Hex strips exactly the prefix DigestFromHex adds.
func TestDigestHexFromHexRoundTrip(t *testing.T) {
	const hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Hex(DigestFromHex(x)) == x.
	if got := primitive.DigestFromHex(hex).Hex(); got != primitive.Sha256(hex) {
		t.Errorf("Hex(DigestFromHex(%q)) = %q, want %q", hex, got, hex)
	}

	// DigestFromHex(Hex(d)) == d.
	d := primitive.Digest("sha256:" + hex)
	if got := primitive.DigestFromHex(string(d.Hex())); got != d {
		t.Errorf("DigestFromHex(Hex(%q)) = %q, want %q", d, got, d)
	}
}
