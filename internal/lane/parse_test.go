package lane_test

import (
	"strings"
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

// --------------------------------------------------------------------------.
// TestParse -- success cases.
// --------------------------------------------------------------------------.

func TestParse_ValidMinimal(t *testing.T) {
	p, err := lane.Parse("testdata/valid_minimal.yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Name != "test-lane" {
		t.Errorf("name = %q, want test-lane", p.Name)
	}
	if len(p.Steps) != 1 {
		t.Fatalf("step count = %d, want 1", len(p.Steps))
	}
	if p.Steps[0].Name != "build" {
		t.Errorf("step name = %q, want build", p.Steps[0].Name)
	}
	if p.Steps[0].Image != "golang:1.22" {
		t.Errorf("image = %q, want golang:1.22", p.Steps[0].Image)
	}
	if len(p.Steps[0].Outputs) != 1 {
		t.Errorf("output count = %d, want 1", len(p.Steps[0].Outputs))
	}
}

func TestParse_ValidDeploy(t *testing.T) {
	p, err := lane.Parse("testdata/valid_deploy.yaml")
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
	if deployStep.Deploy.Method.Type() != "registry" {
		t.Errorf("deploy method type = %q, want registry", deployStep.Deploy.Method.Type())
	}
}

// --------------------------------------------------------------------------.
// TestParse -- error cases.
// --------------------------------------------------------------------------.

func TestParse_Nonexistent(t *testing.T) {
	_, err := lane.Parse("testdata/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "read:") && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error should mention read failure: %v", err)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := lane.Parse("testdata/invalid_yaml.yaml")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "yaml parse") {
		t.Errorf("error should mention yaml parse: %v", err)
	}
}

func TestParse_InvalidSchema(t *testing.T) {
	_, err := lane.Parse("testdata/invalid_schema.yaml")
	if err == nil {
		t.Fatal("expected error for schema violation")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("error should mention validation: %v", err)
	}
}

func TestParse_StepMultiImage(t *testing.T) {
	_, err := lane.Parse("testdata/invalid_step_multi.yaml")
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
			name:    "absolute output path is valid",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Outputs: []lane.OutputSpec{{Path: "/src/node_modules"}}}}},
			wantErr: "",
		},
		{
			name:    "relative output path rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Outputs: []lane.OutputSpec{{Path: "out.txt"}}}}},
			wantErr: "must be an absolute container path",
		},
		{
			name:    "non-canonical output path rejected",
			lane:    &lane.Lane{Steps: []lane.Step{{Name: "s", Outputs: []lane.OutputSpec{{Path: "/src/../etc/passwd"}}}}},
			wantErr: "is not canonical",
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
	_, err := lane.Parse("testdata/invalid_path_traversal.yaml")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "relative to lane root") {
		t.Errorf("error should mention path constraint: %v", err)
	}
}
