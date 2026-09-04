package primitive_test

import (
	"testing"

	"github.com/istr/strike/internal/primitive"
)

func TestPortString(t *testing.T) {
	tests := []struct {
		name string
		want string
		in   primitive.Port
	}{
		{name: "lowest", in: 1, want: "1"},
		{name: "https", in: 443, want: "443"},
		{name: "highest", in: 65535, want: "65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
