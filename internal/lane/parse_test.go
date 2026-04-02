package lane_test

import (
	"testing"
	"time"

	"github.com/istr/strike/internal/lane"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   lane.Duration
		name    string
		def     time.Duration
		want    time.Duration
		wantErr bool
	}{
		{input: "30s", name: "seconds", def: time.Minute, want: 30 * time.Second},
		{input: "5m", name: "minutes", def: time.Minute, want: 5 * time.Minute},
		{input: "1h", name: "hours", def: time.Minute, want: time.Hour},
		{input: "", name: "empty uses default", def: time.Minute, want: time.Minute},
		{input: "invalid", name: "invalid", def: time.Minute, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lane.ParseDuration(tt.input, tt.def)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
