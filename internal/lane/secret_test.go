package lane_test

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func randomHex(t *testing.T) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf[:])
}

func TestReadSecret_EnvSet(t *testing.T) {
	val := randomHex(t)
	t.Setenv("STRIKE_TEST_SECRET", val)
	root := openTestRoot(t, t.TempDir())
	got, err := lane.ReadSecret("env://STRIKE_TEST_SECRET", root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != val {
		t.Fatalf("got %q, want %q", got, val)
	}
}

func TestReadSecret_EnvUnset(t *testing.T) {
	root := openTestRoot(t, t.TempDir())
	_, err := lane.ReadSecret("env://STRIKE_TEST_UNSET_VAR_XYZ", root)
	if err == nil {
		t.Fatal("expected error for unset env variable")
	}
}

func TestReadSecret_FileExists(t *testing.T) {
	want := randomHex(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, dir)
	got, err := lane.ReadSecret(lane.SecretSource("file://secret.txt"), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadSecret_FileMissing(t *testing.T) {
	root := openTestRoot(t, t.TempDir())
	_, err := lane.ReadSecret("file://nonexistent.txt", root)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadSecret_UnknownScheme(t *testing.T) {
	root := openTestRoot(t, t.TempDir())
	_, err := lane.ReadSecret("ftp://example.com/secret", root)
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestResolveSecrets_MissingDefinition(t *testing.T) {
	refs := []lane.SecretRef{{Name: "missing", Env: "MISSING"}}
	sources := map[string]lane.SecretSource{}
	root := openTestRoot(t, t.TempDir())

	_, err := lane.ResolveSecrets(refs, sources, root)
	if err == nil {
		t.Fatal("expected error for missing secret definition")
	}
}

func TestResolveSecrets_Valid(t *testing.T) {
	valA := randomHex(t)
	valB := randomHex(t)
	t.Setenv("STRIKE_TEST_A", valA)
	t.Setenv("STRIKE_TEST_B", valB)

	nameA := "s_" + randomHex(t)
	nameB := "s_" + randomHex(t)

	refs := []lane.SecretRef{
		{Name: nameA, Env: "OUT_A"},
		{Name: nameB, Env: "OUT_B"},
	}
	defs := map[string]lane.SecretSource{
		nameA: "env://STRIKE_TEST_A",
		nameB: "env://STRIKE_TEST_B",
	}

	root := openTestRoot(t, t.TempDir())
	result, err := lane.ResolveSecrets(refs, defs, root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["OUT_A"] != valA {
		t.Errorf("OUT_A = %q, want %q", result["OUT_A"], valA)
	}
	if result["OUT_B"] != valB {
		t.Errorf("OUT_B = %q, want %q", result["OUT_B"], valB)
	}
}
