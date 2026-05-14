package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/testutil"
)

func TestWriteTestBinary(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "testbin")
	content := []byte("#!/bin/sh\necho ok\n")

	testutil.WriteTestBinary(t, binPath, content)

	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
	got := testutil.ReadTemp(t, dir, "testbin")
	if string(got) != string(content) {
		t.Errorf("content mismatch")
	}
}

func TestReadTemp(t *testing.T) {
	dir := t.TempDir()
	want := []byte("test content")
	if err := os.WriteFile(filepath.Join(dir, "out.txt"), want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := testutil.ReadTemp(t, dir, "out.txt")
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
