// Package registry implements OCI registry operations, content-addressed
// caching, and spec hashing for strike lane artifacts.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// SpecHash computes the spec hash of a step (Merkle tree over the DAG).
// Inputs are the spec hashes of producing steps, not their contents -
// fully computable before execution.
func SpecHash(
	step *lane.Step,
	imageDigest primitive.Digest, // sha256 digest of the image
	inputHashes map[string]primitive.Digest, // step-name -> spec hash of producing step
	sourceHashes map[string]primitive.Digest, // mount-path -> sha256 of source file
) primitive.Digest {
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

	return primitive.DigestFromHex(hex.EncodeToString(h.Sum(nil)))
}

// Tag builds the registry tag from step name and spec hash.
// The hash is truncated to 16 hex characters for OCI tag length constraints.
// Format: registry:step-name-<first16hex>
// Example: ghcr.io/istr/strike-cache:build-package-a3f9c2b1d4e7f801.
func Tag(registry, stepID string, hash primitive.Digest) string {
	short := hash.Hex()
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("%s:%s-%s", registry, stepID, short)
}

// wrapRepo is the repository portion of a wrapped image's local reference,
// shared by WrapTag (tag form) and WrapDigest (digest form) so the RepoDigest
// libpod records at ImageTag time matches the reference a consumer step is
// executed against.
func wrapRepo(laneID, stepID primitive.Identifier) string {
	return fmt.Sprintf("localhost/strike/%s/%s", laneID, stepID)
}

// WrapTag builds the local engine tag used by wrapOutputs and input extraction.
// Format: localhost/strike/{laneID}/{stepID}:{specHashHex}.
func WrapTag(laneID, stepID primitive.Identifier, specHash primitive.Digest) string {
	return fmt.Sprintf("%s:%s", wrapRepo(laneID, stepID), specHash.Hex())
}

// WrapDigest builds the content-addressed local reference a step's base image
// is executed against (ADR-045): localhost/strike/{laneID}/{stepID}@{D}. libpod
// records this exact RepoDigest at ImageTag time (see WrapTag), so it resolves
// the locally-loaded image with no registry pull.
func WrapDigest(laneID, stepID primitive.Identifier, digest primitive.Digest) string {
	return fmt.Sprintf("%s@%s", wrapRepo(laneID, stepID), digest.String())
}

// hashReader computes SHA256 of the data from r.
func hashReader(r io.Reader) (primitive.Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return primitive.DigestFromHex(hex.EncodeToString(h.Sum(nil))), nil
}

// HashFile computes SHA256 of a file within the given root scope.
func HashFile(root *os.Root, path string) (hash primitive.Digest, err error) {
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

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedDigestMapKeys(m map[string]primitive.Digest) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
