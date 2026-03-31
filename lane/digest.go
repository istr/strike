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

// SourceDigest computes the sha256 digest of a local path (file or directory).
func SourceDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("source digest %q: %w", path, err)
	}
	if info.IsDir() {
		return dirDigest(path)
	}
	return fileDigest(path)
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// dirDigest hashes all files in a directory tree, sorted by relative path.
// Includes the relative path in the hash to distinguish files with identical content.
func dirDigest(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		h.Write([]byte(rel))
		content, err := os.ReadFile(path)
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		h.Write(content)
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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

	// Args (in order — order matters for commands)
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

// ResolveInputDigests resolves all input digests for a step from the lane state,
// and computes source digests for source mounts. Returns the combined map.
func ResolveInputDigests(step *Step, state *State, laneRoot string) (map[string]string, error) {
	digests := make(map[string]string)

	for _, inp := range step.Inputs {
		d, err := InputDigest(inp, state)
		if err != nil {
			return nil, err
		}
		digests["input:"+inp.Name] = d
	}

	for _, src := range step.Sources {
		path := src.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(laneRoot, path)
		}
		d, err := SourceDigest(path)
		if err != nil {
			return nil, err
		}
		digests["source:"+src.Mount] = d
	}

	return digests, nil
}
