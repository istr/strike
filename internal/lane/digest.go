package lane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// SourceDigest computes the sha256 digest of a local path (file or directory)
// within the given root scope.
func SourceDigest(root *os.Root, laneDir, path string) (string, error) {
	info, err := root.Stat(path)
	if err != nil {
		return "", fmt.Errorf("source digest %q: %w", path, err)
	}
	if info.IsDir() {
		return dirDigest(root, laneDir, path)
	}
	return fileDigest(root, path)
}

func fileDigest(root *os.Root, path string) (digest string, err error) {
	f, err := root.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// dirDigest hashes all files in a directory tree, sorted by relative path.
// WalkDir enumerates via the absolute path; file reads go through root.Open
// for TOCTOU safety.
func dirDigest(root *os.Root, laneDir, dir string) (string, error) {
	info, err := root.Stat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", dir)
	}

	absDir := filepath.Join(laneDir, dir)
	h := sha256.New()
	err = filepath.WalkDir(absDir, dirDigestWalkFunc(root, absDir, dir, h))
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// dirDigestWalkFunc returns a WalkDir callback that hashes each file
// through the root scope for TOCTOU safety.
func dirDigestWalkFunc(root *os.Root, absDir, dir string, h io.Writer) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
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

// InputDigest resolves the digest for an InputRef from the lane state.
func InputDigest(ref InputRef, state *State) (string, error) {
	a, err := state.Resolve(ref.From)
	if err != nil {
		return "", fmt.Errorf("input %q: %w", ref.Name, err)
	}
	return a.Digest, nil
}

// CacheKey computes a deterministic cache key from a step's inputs.
// Same inputs always produce the same key.
func CacheKey(step *Step, imageDigest string, inputDigests map[string]string) string {
	h := sha256.New()

	// Image identity
	h.Write([]byte(imageDigest))

	// Args (in order -- order matters for commands)
	for _, arg := range step.Args {
		h.Write([]byte(arg))
	}

	// Env vars sorted by key
	envKeys := make([]string, 0, len(step.Env))
	for k := range step.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		h.Write([]byte(k))
		h.Write([]byte("="))
		h.Write([]byte(step.Env[k]))
	}

	// Input digests sorted by name
	inputNames := make([]string, 0, len(inputDigests))
	for k := range inputDigests {
		inputNames = append(inputNames, k)
	}
	sort.Strings(inputNames)
	for _, k := range inputNames {
		h.Write([]byte(k))
		h.Write([]byte("="))
		h.Write([]byte(inputDigests[k]))
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
