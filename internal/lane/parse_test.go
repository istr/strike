package lane_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
)

func mustFilePath(t *testing.T, path string) lane.FilePath {
	t.Helper()
	fp, err := lane.NewFilePath(path)
	if err != nil {
		t.Fatalf("NewFilePath(%q): %v", path, err)
	}
	return fp
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   *lane.Duration
		name    string
		def     clock.Duration
		want    clock.Duration
		wantErr bool
	}{
		{input: lane.Ptr(lane.Duration("30s")), name: "seconds", def: clock.Minute, want: 30 * clock.Second},
		{input: lane.Ptr(lane.Duration("5m")), name: "minutes", def: clock.Minute, want: 5 * clock.Minute},
		{input: lane.Ptr(lane.Duration("1h")), name: "hours", def: clock.Minute, want: clock.Hour},
		{input: nil, name: "nil uses default", def: clock.Minute, want: clock.Minute},
		{input: lane.Ptr(lane.Duration("invalid")), name: "invalid", def: clock.Minute, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lane.ParseDuration(tt.input, tt.def)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%v) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseDuration(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------.
// TestParse -- success cases.
// --------------------------------------------------------------------------.

func TestParse_ValidMinimal(t *testing.T) {
	p, err := lane.Parse(mustFilePath(t, "testdata/valid_minimal.yaml"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Name != "test-lane" {
		t.Errorf("name = %q, want test-lane", p.Name)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("step count = %d, want 2", len(p.Steps))
	}
	if p.Steps[0].Name != "build" {
		t.Errorf("step name = %q, want build", p.Steps[0].Name)
	}
	wantImage := lane.ImageRef("docker.io/library/golang@sha256:abababababababababababababababababababababababababababababababab")
	if p.Steps[0].Image == nil || *p.Steps[0].Image != wantImage {
		t.Errorf("image = %v, want %s", p.Steps[0].Image, wantImage)
	}
	if len(p.Steps[0].Outputs) != 1 {
		t.Errorf("output count = %d, want 1", len(p.Steps[0].Outputs))
	}
	if p.Steps[1].Name != "deploy" {
		t.Errorf("step[1] name = %q, want deploy", p.Steps[1].Name)
	}
	if p.Steps[1].Deploy == nil {
		t.Error("step[1].Deploy is nil, want non-nil")
	}
}

func TestParse_ValidDeployOnly(t *testing.T) {
	yaml := []byte(`
name: deploy-only
lane_id: deploy-only
registry: localhost:5555/test
secrets: {}
resolver:
  host: "1.1.1.1:853"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - name: deploy
    deploy:
      method:
        type: registry
        source: localhost:5555/test/image:latest
        target: registry.example.com/app:latest
      artifacts: {}
      target:
        id: deploy-only-target
        type: registry
        description: deploy-only lane
      attestation:
        pre_state:
          required: false
          capture: []
        post_state:
          required: false
          capture: []
    args: []
    env: {}
    inputs: []
    secrets: []
    outputs: []
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "lane.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := lane.Parse(mustFilePath(t, path))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Steps) != 1 {
		t.Fatalf("step count = %d, want 1", len(p.Steps))
	}
	if p.Steps[0].Deploy == nil {
		t.Error("step[0].Deploy is nil, want non-nil")
	}
}

func TestParse_NonPinnedImageRejected(t *testing.T) {
	_, err := lane.Parse(mustFilePath(t, "testdata/invalid_image_not_pinned.yaml"))
	if err == nil {
		t.Fatal("expected error for non-pinned image")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("error should mention validation: %v", err)
	}
}

func TestParse_ForceRunTrue(t *testing.T) {
	p, err := lane.Parse(mustFilePath(t, "testdata/valid_force_run.yaml"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Steps[0].ForceRun {
		t.Error("expected ForceRun=true")
	}
}

func TestParse_ForceRunDefaultFalse(t *testing.T) {
	p, err := lane.Parse(mustFilePath(t, "testdata/valid_minimal.yaml"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Steps[0].ForceRun {
		t.Error("expected ForceRun=false by default")
	}
}

func TestParse_ValidDeploy(t *testing.T) {
	p, err := lane.Parse(mustFilePath(t, "testdata/valid_deploy.yaml"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("step count = %d, want 2", len(p.Steps))
	}
	deployStep := p.Steps[1]
	if deployStep.Deploy == nil {
		t.Fatal("deploy spec should be non-nil")
	}
	if deployStep.Deploy.Method.MethodType() != "registry" {
		t.Errorf("deploy method type = %q, want registry", deployStep.Deploy.Method.MethodType())
	}
}

// --------------------------------------------------------------------------.
// TestParse -- error cases.
// --------------------------------------------------------------------------.

func TestParse_Nonexistent(t *testing.T) {
	_, err := lane.NewFilePath("testdata/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error should mention no such file: %v", err)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := lane.Parse(mustFilePath(t, "testdata/invalid_yaml.yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "yaml parse") {
		t.Errorf("error should mention yaml parse: %v", err)
	}
}

func TestParse_InvalidSchema(t *testing.T) {
	_, err := lane.Parse(mustFilePath(t, "testdata/invalid_schema.yaml"))
	if err == nil {
		t.Fatal("expected error for schema violation")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("error should mention validation: %v", err)
	}
}

func TestParse_StepMultiImage(t *testing.T) {
	_, err := lane.Parse(mustFilePath(t, "testdata/invalid_step_multi.yaml"))
	if err == nil {
		t.Fatal("expected error for step with both image and pack")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("error should mention 'exactly one': %v", err)
	}
}

func TestValidatePaths(t *testing.T) {
	tests := []struct {
		name    string
		lane    *lane.Lane
		wantErr string
	}{
		{
			name:    "relative output path is valid",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Workdir: lane.Ptr(lane.AbsPath("/work")), Outputs: []lane.OutputSpec{{Path: lane.Ptr(lane.RelPath("node_modules"))}}}}},
			wantErr: "",
		},
		{
			name:    "absolute output path rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Workdir: lane.Ptr(lane.AbsPath("/work")), Outputs: []lane.OutputSpec{{Path: lane.Ptr(lane.RelPath("/out.txt"))}}}}},
			wantErr: "must be relative",
		},
		{
			name:    "non-canonical output path rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Workdir: lane.Ptr(lane.AbsPath("/work")), Outputs: []lane.OutputSpec{{Path: lane.Ptr(lane.RelPath("src/../etc/passwd"))}}}}},
			wantErr: "must be canonical",
		},
		{
			name:    "outputs without workdir rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Outputs: []lane.OutputSpec{{Path: lane.Ptr(lane.RelPath("out"))}}}}},
			wantErr: "declares outputs but no workdir",
		},
		{
			name:    "workdir absolute canonical",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/src"))}}},
			wantErr: "",
		},
		{
			name:    "workdir root",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/"))}}},
			wantErr: "",
		},
		{
			name:    "workdir nested",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/out/www"))}}},
			wantErr: "",
		},
		{
			name:    "workdir relative rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("src"))}}},
			wantErr: "must be absolute",
		},
		{
			name:    "workdir dot-dot rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/src/../etc"))}}},
			wantErr: "must be canonical",
		},
		{
			name:    "workdir dot rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/src/./build"))}}},
			wantErr: "must be canonical",
		},
		{
			name:    "workdir double slash rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/src//out"))}}},
			wantErr: "must be canonical",
		},
		{
			name:    "workdir trailing slash rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Image: lane.Ptr(lane.ImageRef("img")), Workdir: lane.Ptr(lane.AbsPath("/src/"))}}},
			wantErr: "must be canonical",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lane.ValidatePaths(tt.lane)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParse_PathTraversal(t *testing.T) {
	_, err := lane.Parse(mustFilePath(t, "testdata/invalid_path_traversal.yaml"))
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("error should be a validation error: %v", err)
	}
}

// TestParse_DisjunctionErrorIsReadable ensures schema validation
// errors do not leak the "N errors in empty disjunction" aggregate
// marker into user-visible output. Regression guard for the
// FormatValidationError integration.
func TestParse_DisjunctionErrorIsReadable(t *testing.T) {
	// Use whichever discriminator-bearing field exists on the
	// current branch. Adjust if the lane schema has shifted.
	bad := []byte(`
name: test
registry: localhost:5555/test
secrets: {}
resolver:
  host: "1.1.1.1:853"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - name: bad-deploy
    deploy:
      method:
        type: nonsense
        image: img@sha256:0000000000000000000000000000000000000000000000000000000000000000
      artifacts: {}
      target:
        type: registry
        description: x
      attestation:
        pre_state: {required: false, capture: []}
        post_state: {required: false, capture: []}
        drift: {detect: false, on_drift: warn}
`)

	dir := t.TempDir()
	path := filepath.Join(dir, "lane.yaml")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := lane.Parse(mustFilePath(t, path))
	if err == nil {
		t.Fatal("expected parse error for invalid deploy method type")
	}
	msg := err.Error()
	if strings.Contains(msg, "errors in empty disjunction") {
		t.Errorf("parse error contains aggregate marker: %s", msg)
	}
	if !strings.Contains(msg, "validation:") {
		t.Errorf("parse error missing validation prefix: %s", msg)
	}
}

// TestParse_RelPathValidation exercises the CUE regex for #RelPath.
func TestParse_RelPathValidation(t *testing.T) {
	tmpl := `
name: test
lane_id: test
registry: localhost:5555/test
secrets: {}
resolver:
  host: "1.1.1.1:853"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - name: src
    image: img@sha256:abababababababababababababababababababababababababababababababab
    args: ["true"]
    workdir: /work
    env: {}
    inputs: []
    secrets: []
    outputs:
      - { name: tree, type: directory, path: tree }
  - name: consumer
    image: img@sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
    args: ["true"]
    env: {}
    inputs:
      - from: src.tree
        subpath: %s
        mount: /in/x
    secrets: []
    outputs: []
  - name: deploy
    deploy:
      method:
        type: registry
        source: localhost:5555/test/image:latest
        target: registry.example.com/app:latest
      artifacts: {}
      target:
        id: d1-minimal-target
        type: registry
        description: minimal deploy step for D1
      attestation:
        pre_state:
          required: false
          capture: []
        post_state:
          required: false
          capture: []
    args: []
    env: {}
    inputs: []
    secrets: []
    outputs: []
`

	tests := []struct {
		name    string
		subpath string
		valid   bool
	}{
		{"clean_relative", "package.json", true},
		{"nested_relative", "packages/sub/file.txt", true},
		{"leading_slash", "/abs/path", false},
		{"bare_dotdot", "..", false},
		{"leading_dotdot", "../escape", false},
		{"embedded_dotdot", "sub/../escape", false},
		{"bare_dot", ".", false},
		{"embedded_dot", "sub/./file", false},
		{"double_slash", "a//b", false},
		{"trailing_slash", "trailing/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := fmt.Sprintf(tmpl, tt.subpath)
			dir := t.TempDir()
			path := filepath.Join(dir, "lane.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := lane.Parse(mustFilePath(t, path))
			if tt.valid {
				if err != nil {
					t.Errorf("expected valid subpath %q, got error: %v", tt.subpath, err)
				}
			} else {
				if err == nil {
					t.Errorf("expected invalid subpath %q to be rejected", tt.subpath)
				}
			}
		})
	}
}
