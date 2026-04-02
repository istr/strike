// Package registry implements OCI registry operations, content-addressed
// caching, and spec hashing for strike lane artifacts.
package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/istr/strike/internal/lane"
)

// SpecHash computes the spec hash of a step (Merkle tree over the DAG).
// Inputs are the spec hashes of producing steps, not their contents -
// fully computable before execution.
func SpecHash(
	step *lane.Step,
	imageDigest string, // sha256 digest of the image
	inputHashes map[string]string, // step-name -> spec hash of producing step
	sourceHashes map[string]string, // mount-path -> sha256 of source file
) string {
	h := sha256.New()

	h.Write([]byte(imageDigest))

	args := append([]string{}, step.Args...)
	sort.Strings(args)
	for _, a := range args {
		h.Write([]byte(a))
	}

	// Env vars sorted by key for determinism
	envKeys := sortedKeys(step.Env)
	for _, k := range envKeys {
		h.Write([]byte(k + "=" + step.Env[k]))
	}

	// Input hashes sorted by name for determinism
	names := sortedKeys(inputHashes)
	for _, n := range names {
		h.Write([]byte(n + "=" + inputHashes[n]))
	}

	// Source hashes sorted by path
	paths := sortedKeys(sourceHashes)
	for _, p := range paths {
		h.Write([]byte(p + "=" + sourceHashes[p]))
	}

	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// Tag builds the registry tag from step name and hash.
// Format: registry:step-name-hash16
// Example: ghcr.io/istr/strike-cache:build-package-a3f9c2b1d4e7f801.
func Tag(registry, stepName, hash string) string {
	return fmt.Sprintf("%s:%s-%s", registry, stepName, hash)
}

// HashPath computes SHA256 of a file or directory within the given root scope.
func HashPath(root *os.Root, laneDir, path string) (string, error) {
	info, err := root.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return hashDir(root, laneDir, path)
	}
	return HashFile(root, path)
}

// HashFile computes SHA256 of a file within the given root scope.
func HashFile(root *os.Root, path string) (hash string, err error) {
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
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// HashFileAbs hashes a file given as an absolute path from CLI args.
func HashFileAbs(path string) (hash string, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: absolute path from CLI argument, intentional
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
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// hashDir computes SHA256 of all files in a directory (recursive, sorted).
// WalkDir enumerates via the absolute path; file reads go through root.Open
// for TOCTOU safety.
func hashDir(root *os.Root, laneDir, dir string) (string, error) {
	absDir := filepath.Join(laneDir, dir)
	h := sha256.New()
	err := filepath.WalkDir(absDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return nil // skip unreadable files -- they can't affect the build
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

		relToRoot := filepath.Join(dir, rel)
		f, openErr := root.Open(relToRoot)
		if openErr != nil {
			if os.IsPermission(openErr) {
				return nil
			}
			return openErr
		}
		content, readErr := io.ReadAll(f)
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		h.Write([]byte(path))
		h.Write(content)
		return nil
	})
	return fmt.Sprintf("%x", h.Sum(nil)), err
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Cache stores and retrieves step outputs as OCI artifacts.
// Cache entries are content-addressed: the cache key maps to an OCI
// manifest. Tag: cache-<first-12-of-cache-key>.
// Annotation: full cache key for collision detection.
type Cache struct {
	Registry string
}

// CacheTag builds the OCI tag for a cache entry.
// Format: registry/strike-cache:cache-<first12>.
func (c *Cache) CacheTag(key string) string {
	// Strip "sha256:" prefix if present
	k := key
	if len(k) > 7 && k[:7] == "sha256:" {
		k = k[7:]
	}
	short := k
	if len(short) > 12 {
		short = short[:12]
	}
	return fmt.Sprintf("%s/strike-cache:cache-%s", c.Registry, short)
}

const cacheKeyAnnotation = "dev.strike.cache-key"

// Lookup checks local and remote for a cached step result.
// Returns the list of cached artifacts and true if found.
func (c *Cache) Lookup(ctx context.Context, key string, client *Client) ([]lane.Artifact, bool) {
	tag := c.CacheTag(key)

	local, remote := client.Find(ctx, tag)
	if !local && !remote {
		return nil, false
	}

	if remote && !local {
		if err := client.Pull(ctx, tag); err != nil {
			return nil, false
		}
	}

	// Verify the full cache key annotation matches (collision detection)
	fullKey, err := client.InspectAnnotation(ctx, tag, cacheKeyAnnotation)
	if err != nil || fullKey != key {
		return nil, false
	}

	return nil, true // artifacts retrieved via the tag
}
