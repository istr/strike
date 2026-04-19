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

func TestSourceDigestFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "hello.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, tmp)

	d1, err := lane.SourceDigest(root, tmp, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d1.Algorithm != testAlgoSHA256 {
		t.Fatalf("expected sha256: prefix, got %q", d1)
	}

	// Same content -> same digest
	d2, err := lane.SourceDigest(root, tmp, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("same file, different digest: %q vs %q", d1, d2)
	}

	// Different content -> different digest
	if writeErr := os.WriteFile(path, []byte("different"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	d3, err := lane.SourceDigest(root, tmp, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("different content should produce different digest")
	}
}

func TestSourceDigestDir(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "b.go"), []byte("package sub"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, tmp)

	d1, err := lane.SourceDigest(root, tmp, "src")
	if err != nil {
		t.Fatal(err)
	}
	if d1.Algorithm != testAlgoSHA256 {
		t.Fatalf("expected sha256: prefix, got %q", d1)
	}

	// Same content -> same digest (deterministic)
	d2, err := lane.SourceDigest(root, tmp, "src")
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("same directory should produce same digest")
	}

	// Change a file -> different digest
	if writeErr := os.WriteFile(filepath.Join(srcDir, "sub", "b.go"), []byte("package changed"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	d3, err := lane.SourceDigest(root, tmp, "src")
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("changed file should change directory digest")
	}
}

func TestSourceDigestRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := openTestRoot(t, dir)

	// Valid path succeeds
	if _, err := lane.SourceDigest(root, dir, "ok.txt"); err != nil {
		t.Fatalf("valid path failed: %v", err)
	}

	// Traversal path fails
	if _, err := lane.SourceDigest(root, dir, "../../../etc/passwd"); err == nil {
		t.Fatal("expected error for traversal path")
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
		{"top-level symlink to file", setupTopLevelSymlinkFile, "link.txt", "symlink not allowed: link.txt -> real.txt"},
		{"top-level symlink to dir", setupTopLevelSymlinkDir, "link-dir", "symlink not allowed: link-dir -> real-dir"},
	}
}

func TestSourceDigestRejectsSymlinks(t *testing.T) {
	for _, tt := range symlinkTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			tt.setup(t, tmp)
			root := openTestRoot(t, tmp)
			_, err := lane.SourceDigest(root, tmp, tt.path)
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

func setupTopLevelSymlinkFile(t *testing.T, dir string) {
	t.Helper()
	mustWriteFile(t, filepath.Join(dir, "real.txt"), "hello")
	mustSymlink(t, "real.txt", filepath.Join(dir, "link.txt"))
}

func setupTopLevelSymlinkDir(t *testing.T, dir string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(dir, "real-dir"))
	mustWriteFile(t, filepath.Join(dir, "real-dir", "f.go"), "package f")
	mustSymlink(t, "real-dir", filepath.Join(dir, "link-dir"))
}

func TestDirDigestWithSize(t *testing.T) {
	t.Run("sum of file sizes", func(t *testing.T) {
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
	})

	t.Run("empty directory has size zero", func(t *testing.T) {
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
	})

	t.Run("nested files", func(t *testing.T) {
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
	})

	t.Run("digest matches SourceDigest", func(t *testing.T) {
		tmp := t.TempDir()
		mustMkdirAll(t, filepath.Join(tmp, "out"))
		mustWriteFile(t, filepath.Join(tmp, "out", "f.txt"), "content")

		root := openTestRoot(t, tmp)
		d1, _, err := lane.DirDigestWithSize(root, tmp, "out")
		if err != nil {
			t.Fatal(err)
		}
		d2, err := lane.SourceDigest(root, tmp, "out")
		if err != nil {
			t.Fatal(err)
		}
		if d1 != d2 {
			t.Fatalf("DirDigestWithSize digest %q != SourceDigest %q", d1, d2)
		}
	})
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
