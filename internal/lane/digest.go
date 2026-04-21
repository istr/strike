package lane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// rejectSymlink returns an error if absPath is a symlink.
// Returns nil when absPath does not exist (caller handles that case).
func rejectSymlink(absPath, name string) error {
	info, ok := lstat(absPath)
	if !ok || info.Mode()&fs.ModeSymlink == 0 {
		return nil
	}
	target, readErr := os.Readlink(absPath)
	if readErr != nil {
		return fmt.Errorf("symlink not allowed: %s", name)
	}
	return fmt.Errorf("symlink not allowed: %s -> %s", name, target)
}

// lstat wraps os.Lstat, returning (info, true) on success.
func lstat(path string) (fs.FileInfo, bool) {
	info, err := os.Lstat(path)
	return info, err == nil
}

// DirDigestWithSize computes the sha256 digest and total file size of a
// directory tree within the given root scope. Size is the sum of regular
// file sizes (matching du -sb behavior).
func DirDigestWithSize(root *os.Root, laneDir, dir string) (Digest, int64, error) {
	if err := rejectSymlink(filepath.Join(laneDir, dir), dir); err != nil {
		return Digest{}, 0, err
	}
	return dirDigestWithSize(root, laneDir, dir)
}

func dirDigestWithSize(root *os.Root, laneDir, dir string) (Digest, int64, error) {
	info, err := root.Stat(dir)
	if err != nil {
		return Digest{}, 0, err
	}
	if !info.IsDir() {
		return Digest{}, 0, fmt.Errorf("%q is not a directory", dir)
	}

	absDir := filepath.Join(laneDir, dir)
	h := sha256.New()
	var totalSize int64
	err = filepath.WalkDir(absDir, dirDigestWalkFunc(root, absDir, dir, h, &totalSize))
	if err != nil {
		return Digest{}, 0, err
	}
	return Digest{Algorithm: "sha256", Hex: hex.EncodeToString(h.Sum(nil))}, totalSize, nil
}

// dirDigestWalkFunc returns a WalkDir callback that hashes each file
// through the root scope for TOCTOU safety.
func dirDigestWalkFunc(root *os.Root, absDir, dir string, h io.Writer, size *int64) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			rel, relErr := filepath.Rel(absDir, path)
			if relErr != nil {
				return relErr
			}
			return rejectSymlink(path, filepath.Join(dir, rel))
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		*size += info.Size()

		rel, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return relErr
		}
		h.Write([]byte(rel)) //nolint:errcheck,gosec // hash.Write never returns an error

		return hashFileFromRoot(root, filepath.Join(dir, rel), h)
	}
}

// hashFileFromRoot reads a file through root and writes its content to h.
func hashFileFromRoot(root *os.Root, relPath string, h io.Writer) (err error) {
	f, err := root.Open(relPath)
	if err != nil {
		if os.IsPermission(err) {
			return nil
		}
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = io.Copy(h, f)
	return err
}
