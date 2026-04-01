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
// Example: ghcr.io/istr/strike-cache:build-package-a3f9c2b1d4e7f801
func Tag(registry, stepName, hash string) string {
	return fmt.Sprintf("%s:%s-%s", registry, stepName, hash)
}

// HashPath computes SHA256 of a file or directory.
func HashPath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return HashDir(path)
	}
	return HashFile(path)
}

// HashFile computes SHA256 of a source file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// HashDir computes SHA256 of all files in a directory (recursive, sorted).
func HashDir(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil // skip unreadable files -- they can't affect the build
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
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

// RegistryCache stores and retrieves step outputs as OCI artifacts.
// Cache entries are content-addressed: the cache key maps to an OCI
// manifest. Tag: cache-<first-12-of-cache-key>.
// Annotation: full cache key for collision detection.
type RegistryCache struct {
	Registry string
}

// CacheTag builds the OCI tag for a cache entry.
// Format: registry/strike-cache:cache-<first12>
func (c *RegistryCache) CacheTag(key string) string {
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
func (c *RegistryCache) Lookup(ctx context.Context, key string, client *Client) ([]lane.Artifact, bool) {
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

// Store pushes step outputs to the registry as a cache entry.
func (c *RegistryCache) Store(ctx context.Context, key string, client *Client, tag string) error {
	if err := client.PushArtifact(ctx, tag); err != nil {
		return fmt.Errorf("cache store %q: %w", tag, err)
	}
	return nil
}
