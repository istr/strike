// Package registry implements OCI registry operations, content-addressed
// caching, and spec hashing for strike lane artifacts.
package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

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

	return "sha256:" + fmt.Sprintf("%x", h.Sum(nil))
}

// Tag builds the registry tag from step name and spec hash.
// The hash is truncated to 16 hex characters for OCI tag length constraints.
// Format: registry:step-name-<first16hex>
// Example: ghcr.io/istr/strike-cache:build-package-a3f9c2b1d4e7f801.
func Tag(registry, stepName, hash string) string {
	short := strings.TrimPrefix(hash, "sha256:")
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("%s:%s-%s", registry, stepName, short)
}

// HashPath computes SHA256 of a file or directory within the given root scope.
// Returns a typed digest in "sha256:<hex>" format.
func HashPath(root *os.Root, laneDir, path string) (string, error) {
	return lane.SourceDigest(root, laneDir, path)
}

// hashReader computes SHA256 of the data from r.
func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// HashFile computes SHA256 of a file within the given root scope.
// Returns a typed digest in "sha256:<hex>" format.
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
	return hashReader(f)
}

// HashFileAbs hashes a file given as an absolute path from CLI args.
// Returns a typed digest in "sha256:<hex>" format.
func HashFileAbs(path string) (hash string, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is an absolute file path from step execution, not web input
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return hashReader(f)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CacheKeyAnnotation is the OCI annotation key that stores the full spec
// hash for collision detection. Tags are truncated to 16 hex chars, so
// the annotation carries the full hash to verify exact matches.
const CacheKeyAnnotation = "dev.strike.cache-key"

// Lookup checks local and remote for a cached step result.
// After finding a cached image by tag, it verifies the full spec hash
// annotation to prevent collisions from tag truncation.
// Returns true if a verified cache hit was found.
func Lookup(ctx context.Context, client *Client, tag, specHash string) bool {
	local, remote := client.Find(ctx, tag)
	if !local && !remote {
		return false
	}

	if remote && !local {
		if err := client.Pull(ctx, tag); err != nil {
			return false
		}
	}

	// Verify the full spec hash annotation matches (collision detection).
	fullKey, err := client.InspectAnnotation(ctx, tag, CacheKeyAnnotation)
	if err != nil || fullKey != specHash {
		return false
	}

	return true
}
