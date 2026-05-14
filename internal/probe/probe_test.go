package probe_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/probe"
)

func TestStat_NilErrorForRegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := probe.Stat(f)
	if err != nil {
		t.Fatalf("Stat(%q): unexpected error %v", f, err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("info.Mode() = %v, want regular", info.Mode())
	}
}

func TestStat_NotExistErrorForMissing(t *testing.T) {
	f := filepath.Join(t.TempDir(), "absent")
	_, err := probe.Stat(f)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(%q): err = %v, want os.ErrNotExist", f, err)
	}
}

func TestStat_FileInfoReportsDirectory(t *testing.T) {
	d := t.TempDir()
	info, err := probe.Stat(d)
	if err != nil {
		t.Fatalf("Stat(%q): %v", d, err)
	}
	if !info.IsDir() {
		t.Errorf("info.IsDir() = false, want true")
	}
}
