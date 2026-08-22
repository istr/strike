package main

import "testing"

func TestNonASCIIOffsets(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []int
	}{
		{name: "empty", content: "", want: nil},
		{name: "ascii only", content: "package main\n// plain text\n", want: nil},
		{name: "first byte", content: "\u00e4bc\n", want: []int{0}},
		{name: "later line", content: "ok\nok\nb\u00e4d\n", want: []int{7}},
		{name: "one report per line", content: "\u00e4\u00f6\n", want: []int{0}},
		{name: "one per offending line", content: "\u00e4\nx\u00f6\n", want: []int{0, 4}},
		{name: "no trailing newline", content: "a\u2014b", want: []int{1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nonASCIIOffsets([]byte(tt.content))
			if len(got) != len(tt.want) {
				t.Fatalf("offsets = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("offsets = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestIsADRFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "ADR-001-engine-via-api-not-exec.md", want: true},
		{name: "ADR-051-deploy-as-sealing-point.md", want: true},
		{name: "ADR-INDEX.md", want: false},
		{name: "ADR-.md", want: false},
		{name: "ADR-001-engine.txt", want: false},
		{name: "README.md", want: false},
		{name: "docs.md", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isADRFile(tt.name); got != tt.want {
				t.Fatalf("isADRFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
