package lane_test

import (
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestDeployMethod_StringAccessors(t *testing.T) {
	m := lane.DeployMethod{
		"type":       "kubernetes",
		"namespace":  "production",
		"strategy":   "apply",
		"source":     "img@sha256:abc",
		"target":     "prod.io/app:latest",
		"image":      "kubectl@sha256:def",
		"kubeconfig": "/home/user/.kube/config",
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"Type", m.Type(), "kubernetes"},
		{"Namespace", m.Namespace(), "production"},
		{"Strategy", m.Strategy(), "apply"},
		{"Source", m.Source(), "img@sha256:abc"},
		{"MethodTarget", m.MethodTarget(), "prod.io/app:latest"},
		{"Image", m.Image(), "kubectl@sha256:def"},
		{"Kubeconfig", m.Kubeconfig(), "/home/user/.kube/config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestDeployMethod_EmptyMap(t *testing.T) {
	m := lane.DeployMethod{}
	if m.Type() != "" {
		t.Errorf("Type() = %q, want empty", m.Type())
	}
	if m.Image() != "" {
		t.Errorf("Image() = %q, want empty", m.Image())
	}
}

func TestDeployMethod_Args(t *testing.T) {
	m := lane.DeployMethod{
		"args": []any{"apply", "-f", "-"},
	}
	args := m.Args()
	if len(args) != 3 {
		t.Fatalf("Args() len = %d, want 3", len(args))
	}
	if args[0] != "apply" || args[1] != "-f" || args[2] != "-" {
		t.Errorf("Args() = %v, want [apply -f -]", args)
	}
}

func TestDeployMethod_ArgsEmpty(t *testing.T) {
	m := lane.DeployMethod{}
	if args := m.Args(); args != nil {
		t.Errorf("Args() = %v, want nil", args)
	}
}

func TestDeployMethod_Env(t *testing.T) {
	m := lane.DeployMethod{
		"env": map[string]any{"FOO": "bar", "BAZ": "qux"},
	}
	env := m.Env()
	if len(env) != 2 {
		t.Fatalf("Env() len = %d, want 2", len(env))
	}
	if env["FOO"] != "bar" {
		t.Errorf("Env[FOO] = %q, want bar", env["FOO"])
	}
	if env["BAZ"] != "qux" {
		t.Errorf("Env[BAZ] = %q, want qux", env["BAZ"])
	}
}

func TestDeployMethod_EnvEmpty(t *testing.T) {
	m := lane.DeployMethod{}
	if env := m.Env(); env != nil {
		t.Errorf("Env() = %v, want nil", env)
	}
}
