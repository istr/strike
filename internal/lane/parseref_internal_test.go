package lane

import (
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		step    string
		output  string
		wantErr string
	}{
		{"valid", "step.output", "step", "output", ""},
		{"multi_dot", "a.b.c", "a", "b.c", ""},
		{"empty", "", "", "", "invalid reference"},
		{"no_dot", "step", "", "", "invalid reference"},
		{"dot_at_start", ".output", "", "", "invalid reference"},
		{"dot_at_end", "step.", "", "", "invalid reference"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step, output, err := parseRef(tt.ref)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if step != tt.step || output != tt.output {
				t.Errorf("parseRef(%q) = (%q, %q), want (%q, %q)", tt.ref, step, output, tt.step, tt.output)
			}
		})
	}
}

func FuzzParseRef(f *testing.F) {
	f.Add("step.output")
	f.Add("")
	f.Add("...")
	f.Add("a.b.c")
	f.Fuzz(func(_ *testing.T, ref string) {
		// Must not panic.
		_, _, err := parseRef(ref)
		_ = err
	})
}
