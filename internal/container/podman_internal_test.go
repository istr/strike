package container

import "testing"

func TestParseLoadedImageID(t *testing.T) {
	tests := []struct {
		name     string
		stream   string
		expected string
	}{
		{
			name:     "standard format",
			stream:   "Loaded image: sha256:abc123\n",
			expected: "sha256:abc123",
		},
		{
			name:     "plural format",
			stream:   "Loaded image(s): sha256:abc123\n",
			expected: "sha256:abc123",
		},
		{
			name:     "no colon prefix",
			stream:   "sha256:abc123",
			expected: "sha256:abc123",
		},
		{
			name:     "empty string",
			stream:   "",
			expected: "",
		},
		{
			name:     "whitespace only",
			stream:   "  \n",
			expected: "",
		},
		{
			name:     "trailing whitespace",
			stream:   "Loaded image: sha256:abc123  \n",
			expected: "sha256:abc123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLoadedImageID(tt.stream)
			if got != tt.expected {
				t.Errorf("parseLoadedImageID(%q) = %q, want %q",
					tt.stream, got, tt.expected)
			}
		})
	}
}
