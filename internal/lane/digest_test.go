package lane_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

const testAlgoSHA256 = "sha256"

func openTestRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close root: %v", err)
		}
	})
	return root
}

func TestDirDigestWithSize_SumOfFileSizes(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "out"))
	mustWriteFile(t, filepath.Join(tmp, "out", "a.bin"), strings.Repeat("a", 100))
	mustWriteFile(t, filepath.Join(tmp, "out", "b.bin"), strings.Repeat("b", 200))
	mustWriteFile(t, filepath.Join(tmp, "out", "c.bin"), strings.Repeat("c", 300))

	root := openTestRoot(t, tmp)
	d, size, err := lane.DirDigestWithSize(root, tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	if d.Algorithm != testAlgoSHA256 {
		t.Fatalf("expected sha256, got %q", d.Algorithm)
	}
	if size != 600 {
		t.Fatalf("expected size 600, got %d", size)
	}
}

func TestDirDigestWithSize_EmptyDir(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "empty"))

	root := openTestRoot(t, tmp)
	_, size, err := lane.DirDigestWithSize(root, tmp, "empty")
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Fatalf("expected size 0, got %d", size)
	}
}

func TestDirDigestWithSize_NestedFiles(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "out", "sub"))
	mustWriteFile(t, filepath.Join(tmp, "out", "a.txt"), strings.Repeat("x", 50))
	mustWriteFile(t, filepath.Join(tmp, "out", "sub", "b.txt"), strings.Repeat("y", 150))

	root := openTestRoot(t, tmp)
	_, size, err := lane.DirDigestWithSize(root, tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	if size != 200 {
		t.Fatalf("expected size 200, got %d", size)
	}
}

func TestDirDigestWithSize_Deterministic(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "out"))
	mustWriteFile(t, filepath.Join(tmp, "out", "f.txt"), "content")

	root := openTestRoot(t, tmp)
	d1, _, err := lane.DirDigestWithSize(root, tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	d2, _, err := lane.DirDigestWithSize(root, tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("same directory produced different digests: %q vs %q", d1, d2)
	}
}

func TestDirDigestWithSize_ContentChange(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "out"))
	mustWriteFile(t, filepath.Join(tmp, "out", "f.txt"), "original")

	root := openTestRoot(t, tmp)
	d1, _, err := lane.DirDigestWithSize(root, tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(tmp, "out", "f.txt"), "changed")
	d2, _, err := lane.DirDigestWithSize(root, tmp, "out")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("different content should produce different digest")
	}
}

// symlinkTestCase describes a symlink rejection test.
type symlinkTestCase struct {
	name    string
	setup   func(t *testing.T, dir string)
	path    string
	wantErr string
}

func symlinkTestCases() []symlinkTestCase {
	return []symlinkTestCase{
		{"no symlinks", setupDirNoSymlinks, "src", ""},
		{"valid symlink to file", setupValidSymlinkFile, "src", "symlink not allowed: src/link.txt -> real.txt"},
		{"broken symlink", setupBrokenSymlink, "src", "symlink not allowed: src/broken -> nonexistent"},
		{"symlink to directory", setupSymlinkDir, "src", "symlink not allowed: src/link-dir -> real-dir"},
		{"nested symlink", setupNestedSymlink, "src", "symlink not allowed: src/sub/link.go -> real.go"},
		{"top-level symlink to dir", setupTopLevelSymlinkDir, "link-dir", "symlink not allowed: link-dir -> real-dir"},
	}
}

func TestDirDigestWithSizeRejectsSymlinks(t *testing.T) {
	for _, tt := range symlinkTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			tt.setup(t, tmp)
			root := openTestRoot(t, tmp)
			_, _, err := lane.DirDigestWithSize(root, tmp, tt.path)
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
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func setupDirNoSymlinks(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "src", "sub"))
	mustWriteFile(t, filepath.Join(dir, "src", "a.go"), "package a")
	mustWriteFile(t, filepath.Join(dir, "src", "sub", "b.go"), "package b")
}

func setupValidSymlinkFile(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "src"))
	mustWriteFile(t, filepath.Join(dir, "src", "real.txt"), "hello")
	mustSymlink(t, "real.txt", filepath.Join(dir, "src", "link.txt"))
}

func setupBrokenSymlink(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "src"))
	mustWriteFile(t, filepath.Join(dir, "src", "real.txt"), "hello")
	mustSymlink(t, "nonexistent", filepath.Join(dir, "src", "broken"))
}

func setupSymlinkDir(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "src", "real-dir"))
	mustWriteFile(t, filepath.Join(dir, "src", "real-dir", "f.go"), "package f")
	mustSymlink(t, "real-dir", filepath.Join(dir, "src", "link-dir"))
}

func setupNestedSymlink(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "src", "sub"))
	mustWriteFile(t, filepath.Join(dir, "src", "sub", "real.go"), "package sub")
	mustSymlink(t, "real.go", filepath.Join(dir, "src", "sub", "link.go"))
}

func setupTopLevelSymlinkDir(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "real-dir"))
	mustWriteFile(t, filepath.Join(dir, "real-dir", "f.go"), "package f")
	mustSymlink(t, "real-dir", filepath.Join(dir, "link-dir"))
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
