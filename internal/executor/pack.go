// Package executor implements container execution and OCI image assembly
// for strike lane steps.
package executor

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
)

// PackOpts is everything pack needs; callers in main.go assemble this.
// InputTars maps each pack file's destination to the canonical content tar
// the caller resolved for it; a pack input never becomes a host path
// (ADR-035, ADR-036).
type PackOpts struct {
	InputTars map[string][]byte
	Spec      *lane.PackSpec
}

// PackResult holds the outputs of a successful pack operation. LayoutTar is
// the assembled image serialized as an OCI layout tar, held in memory and
// handed straight to the engine load; a pack output never becomes a file on
// the controller host (ADR-035).
type PackResult struct {
	Digest    primitive.Digest // "sha256:..." manifest digest of the main image
	LayoutTar []byte
}

// AssembleResult holds the outputs of the pure image assembly step.
// This is the cross-validation boundary: given the same base image, spec,
// and input files, any implementation (Go, Rust, ...) must produce an
// AssembleResult with identical Digest.
type AssembleResult struct {
	Image   v1.Image      // assembled OCI image
	Digest  v1.Hash       // manifest digest
	Subject v1.Descriptor // descriptor for referrer relationships
}

// AssembleImage is the pure computational core of OCI image construction.
// It takes an already-resolved base image and applies layers, config,
// and annotations -- no network I/O, no filesystem access at all.
//
// This function defines the cross-validation surface for a Rust verifier:
// given identical (base, spec, inputTars), the output Digest must match.
// inputTars carries each pack file's content as a canonical tar, so the
// surface is tar canonicalization plus OCI assembly, and never a second
// implementation's reading of a host filesystem.
func AssembleImage(base v1.Image, spec *lane.PackSpec, inputTars map[string][]byte) (*AssembleResult, error) {
	// 1. Add file layers
	img, err := addFileLayers(base, spec.Files, inputTars)
	if err != nil {
		return nil, err
	}

	// 2. Apply image configuration
	img, err = applyConfig(img, spec)
	if err != nil {
		return nil, err
	}

	// 3. Apply annotations
	if spec.Annotations != nil {
		annotated, ok := mutate.Annotations(img, spec.Annotations).(v1.Image)
		if !ok {
			return nil, fmt.Errorf("assemble: unexpected type from mutate.Annotations")
		}
		img = annotated
	}

	// 4. Compute digest -- the cross-validation anchor
	imgDigest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("assemble: image digest: %w", err)
	}
	imgSize, err := img.Size()
	if err != nil {
		return nil, fmt.Errorf("assemble: image size: %w", err)
	}
	imgMediaType, err := img.MediaType()
	if err != nil {
		return nil, fmt.Errorf("assemble: image media type: %w", err)
	}

	return &AssembleResult{
		Image:  img,
		Digest: imgDigest,
		Subject: v1.Descriptor{
			MediaType: imgMediaType,
			Digest:    imgDigest,
			Size:      imgSize,
		},
	}, nil
}

// Pack assembles an OCI image from the given options and returns the result
// as an OCI layout tar in memory. A pack output is an unsigned intermediate:
// signing, SBOM generation, and publication happen once, at deploy
// (ADR-051 D1/D3).
//
// Pack is the orchestrator: it handles I/O (pull, serialize) and delegates to
// the pure AssembleImage for the security-critical computation.
func Pack(opts PackOpts) (*PackResult, error) {
	// 1. Pull and verify the base image (network I/O)
	base, err := pullVerified(opts.Spec.Base)
	if err != nil {
		return nil, fmt.Errorf("pack: pull base image: %w", err)
	}

	// 2. Assemble image -- pure computation, no I/O
	assembled, err := AssembleImage(base, opts.Spec, opts.InputTars)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	// 3. Serialize as an OCI layout tar, in memory.
	layoutTar, err := registry.OCITarFromImage(assembled.Image, map[string]string{
		"org.opencontainers.image.ref.name": assembled.Digest.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	manifestDigest := primitive.Digest(assembled.Digest.String())
	return &PackResult{LayoutTar: layoutTar, Digest: manifestDigest}, nil
}

// addFileLayers appends one layer per file entry, each built from the
// canonical content tar the caller resolved for that destination. The tar is
// already re-rooted, mode-normalized, and containment-checked
// (registry.PackTarFromImage), so assembly does no interpretation of its own.
func addFileLayers(img v1.Image, files []lane.PackFile, inputTars map[string][]byte) (v1.Image, error) {
	for _, f := range files {
		dest := f.Dest.String()
		content, ok := inputTars[dest]
		if !ok {
			return nil, fmt.Errorf("pack: file dest %q: content not resolved", dest)
		}
		opener := func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(content)), nil
		}
		layer, err := tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
		if err != nil {
			return nil, fmt.Errorf("pack: layer for %q: %w", dest, err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			return nil, fmt.Errorf("pack: append layer for %q: %w", dest, err)
		}
	}
	return img, nil
}

// applyConfig applies image configuration (env, entrypoint, cmd, etc.) to the image.
func applyConfig(img v1.Image, spec *lane.PackSpec) (v1.Image, error) {
	if spec.Config == nil {
		return img, nil
	}
	cfg, cfgErr := img.ConfigFile()
	if cfgErr != nil {
		return nil, fmt.Errorf("pack: read config: %w", cfgErr)
	}
	cfg = cfg.DeepCopy()

	if spec.Config.Env != nil {
		keys := make([]string, 0, len(spec.Config.Env))
		for k := range spec.Config.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cfg.Config.Env = appendEnv(cfg.Config.Env, k, spec.Config.Env[k])
		}
	}
	if spec.Config.Entrypoint != nil {
		cfg.Config.Entrypoint = spec.Config.Entrypoint
	}
	if spec.Config.Cmd != nil {
		cfg.Config.Cmd = spec.Config.Cmd
	}
	if spec.Config.Workdir != nil {
		cfg.Config.WorkingDir = spec.Config.Workdir.String()
	}
	if spec.Config.User != nil {
		cfg.Config.User = string(*spec.Config.User)
	}
	if spec.Config.Labels != nil {
		if cfg.Config.Labels == nil {
			cfg.Config.Labels = make(map[string]string)
		}
		for k, v := range spec.Config.Labels {
			cfg.Config.Labels[k] = v
		}
	}

	img, err := mutate.ConfigFile(img, cfg)
	if err != nil {
		return nil, fmt.Errorf("pack: apply config: %w", err)
	}
	return img, nil
}

// pullVerified pulls a remote image by digest-pinned reference.
// For multi-arch images the ref digest pins the index; go-containerregistry
// verifies the index digest on fetch, then resolves to the platform image.
func pullVerified(ref primitive.ImageRef) (v1.Image, error) {
	s := string(ref)
	nameRef, err := name.ParseReference(s)
	if err != nil {
		return nil, fmt.Errorf("parse ref %q: %w", ref, err)
	}

	// Require a digest reference -- tags are not allowed.
	if _, ok := nameRef.(name.Digest); !ok {
		return nil, fmt.Errorf("ref %q must be pinned by digest", ref)
	}

	desc, err := remote.Get(nameRef)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", ref, err)
	}

	// If the ref points to an index, resolve to the platform image.
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("resolve image %q: %w", ref, err)
	}

	return img, nil
}

// appendEnv adds or replaces an environment variable in a list of KEY=VALUE strings.
func appendEnv(env []string, key, value string) []string {
	entry := key + "=" + value
	for i, e := range env {
		if len(e) > len(key) && e[:len(key)+1] == key+"=" {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}
