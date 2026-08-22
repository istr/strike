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

func TestBuildSpecGenerator_TrustVolume(t *testing.T) {
	opts := RunOpts{
		Image:  "img",
		Volume: &VolumeMount{Name: "wd", Dest: "/work"},
		TrustVolumes: []VolumeMount{
			{Name: "strike-ca-test", Dest: "/etc/ssl/certs"},
		},
	}
	spec := buildSpecGenerator(opts)

	if len(spec.Volumes) != 2 {
		t.Fatalf("volumes len = %d, want 2", len(spec.Volumes))
	}
	wd := spec.Volumes[0]
	if wd.Name != "wd" || wd.Dest != "/work" {
		t.Errorf("workdir volume = %+v", wd)
	}
	ca := spec.Volumes[1]
	if ca.Name != "strike-ca-test" {
		t.Errorf("trust volume Name = %q", ca.Name)
	}
	if ca.Dest != "/etc/ssl/certs" {
		t.Errorf("trust volume Dest = %q", ca.Dest)
	}
	hasRO := false
	for _, o := range ca.Options {
		if o == "ro" {
			hasRO = true
		}
	}
	if !hasRO {
		t.Errorf("trust volume Options = %v, want ro", ca.Options)
	}
}

func TestBuildSpecGenerator_TrustVolumeOnly(t *testing.T) {
	opts := RunOpts{
		Image: "img",
		TrustVolumes: []VolumeMount{
			{Name: "strike-ca-test", Dest: "/etc/ssl/certs"},
		},
	}
	spec := buildSpecGenerator(opts)

	if len(spec.Volumes) != 1 {
		t.Fatalf("volumes len = %d, want 1", len(spec.Volumes))
	}
	if spec.Volumes[0].Name != "strike-ca-test" {
		t.Errorf("Name = %q", spec.Volumes[0].Name)
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

func TestParseEngineAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantSock string
		wantBase string
		wantErr  bool
	}{
		{name: "unix socket", addr: "unix:///run/podman.sock", wantSock: "/run/podman.sock", wantBase: "http://d/v5.0.0/libpod"},
		{name: "unix socket not absolute", addr: "unix://run/podman.sock", wantErr: true},
		{name: "unix socket not canonical", addr: "unix:///run/../run/podman.sock", wantErr: true},
		{name: "unix socket empty", addr: "unix://", wantErr: true},
		{name: "https host and port", addr: "https://engine.example:2376", wantBase: "https://engine.example:2376/v5.0.0/libpod"},
		{name: "https host only", addr: "https://engine.example", wantBase: "https://engine.example/v5.0.0/libpod"},
		{name: "https with path", addr: "https://engine.example:2376/sub", wantErr: true},
		{name: "https empty host", addr: "https://", wantErr: true},
		{name: "https port out of range", addr: "https://engine.example:70000", wantErr: true},
		{name: "https port not numeric", addr: "https://engine.example:http", wantErr: true},
		{name: "tcp scheme no longer admitted", addr: "tcp://engine.example:2376", wantErr: true},
		{name: "plaintext http rejected", addr: "http://engine.example:2376", wantErr: true},
		{name: "no scheme", addr: "/run/podman.sock", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEngineAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseEngineAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Unix != (tt.wantSock != "") {
				t.Errorf("Unix = %v, want %v", got.Unix, tt.wantSock != "")
			}
			if got.Socket.String() != tt.wantSock {
				t.Errorf("Socket = %q, want %q", got.Socket, tt.wantSock)
			}
			if base := apiBase(got); base != tt.wantBase {
				t.Errorf("apiBase = %q, want %q", base, tt.wantBase)
			}
		})
	}
}
