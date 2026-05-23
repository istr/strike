package container

import (
	"testing"
)

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

func TestBuildSpecGenerator_NamedVolume(t *testing.T) {
	opts := RunOpts{
		Image:   "img",
		Workdir: "/out/build",
		Volume:  &VolumeMount{Name: "vol1", Dest: "/out/build"},
	}
	spec := buildSpecGenerator(opts)

	raw, ok := spec["volumes"]
	if !ok {
		t.Fatal("spec has no volumes key")
	}
	vols, ok := raw.([]map[string]any)
	if !ok || len(vols) != 1 {
		t.Fatalf("volumes shape = %T len? want one entry", raw)
	}
	if vols[0]["Name"] != "vol1" || vols[0]["Dest"] != "/out/build" {
		t.Errorf("volume entry = %v, want Name=vol1 Dest=/out/build", vols[0])
	}
	if spec["work_dir"] != "/out/build" {
		t.Errorf("work_dir = %v, want /out/build", spec["work_dir"])
	}
}
