package primitive_test

import (
	"testing"

	"github.com/istr/strike/internal/primitive"
)

func TestURIReferenceValidate(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "https url", in: "https://forge.strike.localhost/istr/strike"},
		{name: "scheme-less reference", in: "github.com/o/r"},
		{name: "empty", in: "", wantErr: true},
		{name: "space", in: "https://forge.example/a b", wantErr: true},
		{name: "tab", in: "https://forge.example/a\tb", wantErr: true},
		{name: "bad escape", in: "https://forge.example/%zz", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := primitive.URIReference(tt.in).Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate(%q) = nil, want error", tt.in)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate(%q): %v", tt.in, err)
			}
		})
	}
}

// TestPinScalarStrings covers the String() boundary of the scalar types a
// Fulcio extension pin carries.
func TestPinScalarStrings(t *testing.T) {
	const (
		commit = "0000000000000000000000000000000000000000"
		ref    = "refs/heads/main"
		uri    = "https://forge.strike.localhost/istr/strike"
		env    = "self-hosted"
	)
	got := []string{
		primitive.GitCommit(commit).String(),
		primitive.GitRef(ref).String(),
		primitive.URIReference(uri).String(),
		primitive.RunnerEnvironment(env).String(),
	}
	want := []string{commit, ref, uri, env}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("String() = %q, want %q", got[i], want[i])
		}
	}
}
