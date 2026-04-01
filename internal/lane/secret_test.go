package lane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecret_EnvSet(t *testing.T) {
	t.Setenv("STRIKE_TEST_SECRET", "hunter2")
	val, err := ReadSecret("env://STRIKE_TEST_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "hunter2" {
		t.Fatalf("got %q, want %q", val, "hunter2")
	}
}

func TestReadSecret_EnvUnset(t *testing.T) {
	_, err := ReadSecret("env://STRIKE_TEST_UNSET_VAR_XYZ")
	if err == nil {
		t.Fatal("expected error for unset env variable")
	}
}

func TestReadSecret_FileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	os.WriteFile(path, []byte("file-secret"), 0o600)

	val, err := ReadSecret(SecretSource("file://" + path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "file-secret" {
		t.Fatalf("got %q, want %q", val, "file-secret")
	}
}

func TestReadSecret_FileMissing(t *testing.T) {
	_, err := ReadSecret("file:///nonexistent/path/secret.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadSecret_UnknownScheme(t *testing.T) {
	_, err := ReadSecret("ftp://example.com/secret")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestResolveSecrets_MissingDefinition(t *testing.T) {
	refs := []SecretRef{{Name: "missing", Env: "MISSING"}}
	sources := map[string]SecretSource{}

	_, err := ResolveSecrets(refs, sources)
	if err == nil {
		t.Fatal("expected error for missing secret definition")
	}
}

func TestResolveSecrets_Valid(t *testing.T) {
	t.Setenv("STRIKE_TEST_A", "value-a")
	t.Setenv("STRIKE_TEST_B", "value-b")

	refs := []SecretRef{
		{Name: "secret_a", Env: "SECRET_A"},
		{Name: "secret_b", Env: "SECRET_B"},
	}
	sources := map[string]SecretSource{
		"secret_a": "env://STRIKE_TEST_A",
		"secret_b": "env://STRIKE_TEST_B",
	}

	result, err := ResolveSecrets(refs, sources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["SECRET_A"] != "value-a" {
		t.Errorf("SECRET_A = %q, want %q", result["SECRET_A"], "value-a")
	}
	if result["SECRET_B"] != "value-b" {
		t.Errorf("SECRET_B = %q, want %q", result["SECRET_B"], "value-b")
	}
}
