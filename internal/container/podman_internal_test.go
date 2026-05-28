package container

import (
	"encoding/json"
	"strings"
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

	if len(spec.Volumes) != 1 {
		t.Fatalf("volumes len = %d, want 1", len(spec.Volumes))
	}
	v := spec.Volumes[0]
	if v.Name != "vol1" {
		t.Errorf("volume Name = %q, want vol1", v.Name)
	}
	if v.Dest != "/out/build" {
		t.Errorf("volume Dest = %q, want /out/build", v.Dest)
	}
}

func TestBuildSpecGenerator_ImageVolumes(t *testing.T) {
	opts := DefaultSecureOpts()
	opts.Image = "img"
	opts.ImageVolumes = []ImageVolume{
		{
			Source:      "localhost/strike/lane/src:abc123",
			Destination: "/out/packages",
			SubPath:     "packages",
			ReadWrite:   false,
		},
	}

	spec := buildSpecGenerator(opts)
	if len(spec.ImageVolumes) != 1 {
		t.Fatalf("ImageVolumes len = %d, want 1", len(spec.ImageVolumes))
	}
	iv := spec.ImageVolumes[0]
	if iv.Source != "localhost/strike/lane/src:abc123" {
		t.Errorf("Source = %q", iv.Source)
	}
	if iv.Destination != "/out/packages" {
		t.Errorf("Destination = %q", iv.Destination)
	}
	if iv.SubPath != "packages" {
		t.Errorf("SubPath = %q", iv.SubPath)
	}
	if iv.ReadWrite {
		t.Error("ReadWrite = true, want false")
	}

	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wire := string(b)
	for _, want := range []string{
		`"image_volumes"`,
		`"Source":"localhost/strike/lane/src:abc123"`,
		`"Destination":"/out/packages"`,
		`"SubPath":"packages"`,
		`"ReadWrite":false`,
	} {
		if !strings.Contains(wire, want) {
			t.Errorf("wire missing %s\ngot: %s", want, wire)
		}
	}
}

func TestBuildSpecGenerator_NoImageVolumes(t *testing.T) {
	opts := DefaultSecureOpts()
	opts.Image = "img"
	b, err := json.Marshal(buildSpecGenerator(opts))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "image_volumes") {
		t.Error("image_volumes present when none set (omitempty broken)")
	}
}
