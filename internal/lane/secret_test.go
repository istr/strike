package lane_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	if got.Expose() != val {
		t.Fatalf("got %q, want %q", got.Expose(), val)
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
	if got.Expose() != want {
		t.Fatalf("got %q, want %q", got.Expose(), want)
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
	if result["OUT_A"].Expose() != valA {
		t.Errorf("OUT_A = %q, want %q", result["OUT_A"].Expose(), valA)
	}
	if result["OUT_B"].Expose() != valB {
		t.Errorf("OUT_B = %q, want %q", result["OUT_B"].Expose(), valB)
	}
}

func TestSecretStringRedacted(t *testing.T) {
	const redacted = "[REDACTED]"
	s := lane.NewSecretString("hunter2")

	if s.String() != redacted {
		t.Errorf("String() = %q, want %s", s.String(), redacted)
	}
	if got := s.String(); got != redacted {
		t.Errorf("String() via var = %q, want %s", got, redacted)
	}
	if fmt.Sprintf("%v", s) != redacted {
		t.Error("Sprintf with value verb leaks secret")
	}
	if fmt.Sprintf("%#v", s) != redacted {
		t.Error("Sprintf with GoString verb leaks secret")
	}
	if s.Expose() != "hunter2" {
		t.Errorf("Expose() = %q, want hunter2", s.Expose())
	}

	j, err := s.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(j) != `"`+redacted+`"` {
		t.Errorf("MarshalJSON = %s, want %s", j, redacted)
	}

	txt, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(txt) != redacted {
		t.Errorf("MarshalText = %s, want %s", txt, redacted)
	}
}
