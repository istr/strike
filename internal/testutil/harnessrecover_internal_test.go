package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/container"
)

const testCompose = `name: test-project
services:
  alpha:
    image: example.test/alpha:1.0@sha256:aaaa
  beta:
    image: example.test/beta@sha256:bbbb
  tools:
    profiles: ["tools"]
    image: example.test/tools@sha256:cccc
  built:
    build:
      context: .
`

func writeCompose(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "compose.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write compose fixture: %v", err)
	}
	return path
}

func TestComposeServices(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantProject string
		wantLen     int
		wantErr     bool
	}{
		{"default profile only", testCompose, "test-project", 2, false},
		{"no project name", "services:\n  a:\n    image: x@sha256:dddd\n", "", 0, true},
		{"no default service", "name: p\nservices:\n  a:\n    profiles: [\"t\"]\n    image: x@sha256:dddd\n", "", 0, true},
		{"unpinned image", "name: p\nservices:\n  a:\n    image: x:latest\n", "", 0, true},
		{"malformed yaml", "name: [\n", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, want, err := composeServices(writeCompose(t, tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("composeServices error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if project != tt.wantProject {
				t.Errorf("project = %q, want %q", project, tt.wantProject)
			}
			if len(want) != tt.wantLen {
				t.Fatalf("services = %d, want %d", len(want), tt.wantLen)
			}
			if want["sha256:aaaa"] != "alpha" {
				t.Errorf("digest sha256:aaaa maps to %q, want alpha", want["sha256:aaaa"])
			}
		})
	}
}

func TestComposeServicesMissingFile(t *testing.T) {
	if _, _, err := composeServices(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("composeServices on a missing file returned no error")
	}
}

func TestImageDigest(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"tag and digest", "example.test/a:1.0@sha256:aaaa", "sha256:aaaa", false},
		{"digest only", "example.test/a@sha256:bbbb", "sha256:bbbb", false},
		{"no digest", "example.test/a:1.0", "", true},
		{"empty digest", "example.test/a@", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := imageDigest(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Fatalf("imageDigest error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("imageDigest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHarnessDrift(t *testing.T) {
	want := map[string]string{"sha256:aaaa": "alpha", "sha256:bbbb": "beta"}
	tests := []struct {
		name        string
		got         []container.Summary
		wantToStart int
		wantErr     bool
	}{
		{
			"both stopped",
			[]container.Summary{
				{ID: "1", Image: "reg/alpha@sha256:aaaa", State: "exited", Names: []string{"p_alpha_1"}},
				{ID: "2", Image: "reg/beta@sha256:bbbb", State: "exited", Names: []string{"p_beta_1"}},
			},
			2, false,
		},
		{
			"one already running",
			[]container.Summary{
				{ID: "1", Image: "reg/alpha@sha256:aaaa", State: "running", Names: []string{"p_alpha_1"}},
				{ID: "2", Image: "reg/beta@sha256:bbbb", State: "exited", Names: []string{"p_beta_1"}},
			},
			1, false,
		},
		{
			"count mismatch",
			[]container.Summary{{ID: "1", Image: "reg/alpha@sha256:aaaa", State: "exited"}},
			0, true,
		},
		{
			"undeclared image",
			[]container.Summary{
				{ID: "1", Image: "reg/alpha@sha256:aaaa", State: "exited"},
				{ID: "2", Image: "reg/other@sha256:9999", State: "exited"},
			},
			0, true,
		},
		{
			"duplicate service",
			[]container.Summary{
				{ID: "1", Image: "reg/alpha@sha256:aaaa", State: "exited"},
				{ID: "2", Image: "reg/alpha@sha256:aaaa", State: "exited"},
			},
			0, true,
		},
		{
			"unpinned container image",
			[]container.Summary{
				{ID: "1", Image: "reg/alpha@sha256:aaaa", State: "exited"},
				{ID: "2", Image: "reg/beta:latest", State: "exited"},
			},
			0, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toStart, err := harnessDrift(want, tt.got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("harnessDrift error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if len(toStart) != tt.wantToStart {
				t.Errorf("toStart = %v, want %d entries", toStart, tt.wantToStart)
			}
		})
	}
}

func TestContainerName(t *testing.T) {
	if got := containerName(container.Summary{ID: "abc", Names: []string{"n1", "n2"}}); got != "n1" {
		t.Errorf("containerName = %q, want n1", got)
	}
	if got := containerName(container.Summary{ID: "abc"}); got != "abc" {
		t.Errorf("containerName = %q, want abc", got)
	}
}

func TestEngineAddress(t *testing.T) {
	t.Setenv("CONTAINER_HOST", "https://example.test:1234")
	if got := engineAddress(); got != "https://example.test:1234" {
		t.Errorf("engineAddress = %q, want the set address", got)
	}
	t.Setenv("CONTAINER_HOST", "")
	if got := engineAddress(); got != "(CONTAINER_HOST unset)" {
		t.Errorf("engineAddress = %q, want the unset marker", got)
	}
}
