package primitive_test

import (
	"testing"

	"github.com/istr/strike/internal/primitive"
)

func TestHostString(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "hostname", in: "git.example.com"},
		{name: "ipv4 literal", in: "192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := primitive.Host(tt.in).String(); got != tt.in {
				t.Errorf("String() = %q, want %q", got, tt.in)
			}
		})
	}
}
