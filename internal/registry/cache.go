// Package registry implements OCI registry operations, content-addressed
// caching, and spec hashing for strike lane artifacts.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/istr/strike/internal/lane"
)

// SpecHash computes the spec hash of a step (Merkle tree over the DAG).
// Inputs are the spec hashes of producing steps, not their contents -
// fully computable before execution.
func SpecHash(
	step *lane.Step,
	imageDigest lane.Digest, // sha256 digest of the image
	inputHashes map[string]lane.Digest, // step-name -> spec hash of producing step
	sourceHashes map[string]lane.Digest, // mount-path -> sha256 of source file
) lane.Digest {
	h := sha256.New()

	h.Write([]byte(imageDigest.String()))

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
	names := sortedDigestMapKeys(inputHashes)
	for _, n := range names {
		h.Write([]byte(n + "=" + inputHashes[n].String()))
	}

	// Source hashes sorted by path
	paths := sortedDigestMapKeys(sourceHashes)
	for _, p := range paths {
		h.Write([]byte(p + "=" + sourceHashes[p].String()))
	}

	return lane.Digest{Algorithm: "sha256", Hex: hex.EncodeToString(h.Sum(nil))}
}

// Tag builds the registry tag from step name and spec hash.
// The hash is truncated to 16 hex characters for OCI tag length constraints.
// Format: registry:step-name-<first16hex>
// Example: ghcr.io/istr/strike-cache:build-package-a3f9c2b1d4e7f801.
func Tag(registry, stepName string, hash lane.Digest) string {
	short := hash.Hex
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("%s:%s-%s", registry, stepName, short)
}

// HashPath computes SHA256 of a file or directory within the given root scope.
// Returns a typed digest.
func HashPath(root *os.Root, laneDir, path string) (lane.Digest, error) {
	return lane.SourceDigest(root, laneDir, path)
}

// hashReader computes SHA256 of the data from r.
func hashReader(r io.Reader) (lane.Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return lane.Digest{}, err
	}
	return lane.Digest{Algorithm: "sha256", Hex: hex.EncodeToString(h.Sum(nil))}, nil
}

// HashFile computes SHA256 of a file within the given root scope.
func HashFile(root *os.Root, path string) (hash lane.Digest, err error) {
	f, err := root.Open(path)
	if err != nil {
		return lane.Digest{}, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return hashReader(f)
}

// HashFileAbs hashes a file given as an absolute path from CLI args.
func HashFileAbs(path string) (hash lane.Digest, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is an absolute file path from step execution, not web input
	if err != nil {
		return lane.Digest{}, err
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

func sortedDigestMapKeys(m map[string]lane.Digest) []string {
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
