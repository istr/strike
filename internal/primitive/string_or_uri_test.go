package primitive_test

import (
	"testing"

	"github.com/istr/strike/internal/primitive"
)

func TestStringOrURIValidate(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "email", in: "tester@strike.localhost"},
		{name: "https uri", in: "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main"},
		{name: "spiffe uri", in: "spiffe://example.org/ns/ci/sa/builder"},
		{name: "empty", in: "", wantErr: true},
		{name: "colon in first path segment", in: "1tester:example.com", wantErr: true},
		{name: "colon without scheme", in: "/signer:example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := primitive.StringOrURI(tt.in).Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate(%q) = nil, want error", tt.in)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate(%q): %v", tt.in, err)
			}
		})
	}
}

func TestStringOrURIString(t *testing.T) {
	const in = "tester@strike.localhost"
	if got := primitive.StringOrURI(in).String(); got != in {
		t.Errorf("String() = %q, want %q", got, in)
	}
}
