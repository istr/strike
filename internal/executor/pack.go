// Package executor implements container execution, OCI image assembly,
// signing, and SBOM generation for strike lane steps.
package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
)

// PackOpts is everything pack needs; callers in main.go assemble this.
type PackOpts struct {
	InputPaths  map[string]string
	Spec        *lane.PackSpec
	State       *lane.State
	OutputRoot  *os.Root     // root-scoped output directory
	Rekor       *RekorClient // optional Rekor transparency log client
	OutputName  string       // filename within OutputRoot
	SigningKey  []byte
	KeyPassword []byte
}

// PackResult holds the outputs of a successful pack operation.
type PackResult struct {
	Rekor  *lane.RekorEntry // verified Rekor entry (nil when Rekor is not configured)
	Digest lane.Digest      // "sha256:..." manifest digest of the main image
}

// AssembleResult holds the outputs of the pure image assembly step.
// This is the cross-validation boundary: given the same base image, spec,
// and input files, any implementation (Go, Rust, ...) must produce an
// AssembleResult with identical Digest.
type AssembleResult struct {
	Image      v1.Image      // assembled OCI image
	Digest     v1.Hash       // manifest digest
	Subject    v1.Descriptor // descriptor for referrer relationships
	BinaryPath string        // host path of first binary (for SBOM)
}

// AssembleImage is the pure computational core of OCI image construction.
// It takes an already-resolved base image and applies layers, config,
// and annotations — no network I/O, no filesystem writes.
//
// This function defines the cross-validation surface for a Rust verifier:
// given identical (base, spec, inputPaths), the output Digest must match.
func AssembleImage(base v1.Image, spec *lane.PackSpec, inputPaths map[string]string) (*AssembleResult, error) {
	// 1. Add file layers
	img, binaryPath, err := addFileLayers(base, spec.Files, inputPaths)
	if err != nil {
		return nil, err
	}

	// 2. Add config file layers (literal content)
	img, err = addConfigFileLayers(img, spec.Config_files)
	if err != nil {
		return nil, err
	}

	// 3. Apply image configuration
	img, err = applyConfig(img, spec)
	if err != nil {
		return nil, err
	}

	// 4. Apply annotations
	if spec.Annotations != nil {
		annotated, ok := mutate.Annotations(img, spec.Annotations).(v1.Image)
		if !ok {
			return nil, fmt.Errorf("assemble: unexpected type from mutate.Annotations")
		}
		img = annotated
	}

	// 5. Compute digest — the cross-validation anchor
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
		Image:      img,
		Digest:     imgDigest,
		BinaryPath: binaryPath,
		Subject: v1.Descriptor{
			MediaType: imgMediaType,
			Digest:    imgDigest,
			Size:      imgSize,
		},
	}, nil
}

// Pack assembles an OCI image from the given options, generates an SBOM,
// signs the manifest, and writes the result as an OCI layout tar.
//
// Pack is the orchestrator: it handles I/O (pull, write) and delegates
// to pure functions (AssembleImage, SignManifest, GenerateSBOM) for the
// security-critical computations.
func Pack(ctx context.Context, opts PackOpts) (*PackResult, error) {
	if opts.SigningKey == nil {
		return nil, fmt.Errorf("pack: signing key is required; keyless signing is not yet implemented")
	}

	// 1. Pull and verify the base image (network I/O)
	base, err := pullVerified(string(opts.Spec.Base))
	if err != nil {
		return nil, fmt.Errorf("pack: pull base image: %w", err)
	}

	// 2. Assemble image — pure computation, no I/O
	assembled, err := AssembleImage(base, opts.Spec, opts.InputPaths)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	// 3. Generate SBOM (reads binary buildinfo + probes remote registry)
	buildTime := clock.Reproducible()
	sbomBytes, err := GenerateSBOM(assembled.BinaryPath, assembled.Digest.String(), string(opts.Spec.Base), buildTime)
	if err != nil {
		return nil, fmt.Errorf("pack: sbom: %w", err)
	}
	sbomImage, err := artifactImage(sbomBytes, "application/vnd.cyclonedx+json", assembled.Subject)
	if err != nil {
		return nil, fmt.Errorf("pack: SBOM artifact: %w", err)
	}

	// 4. Sign the image manifest digest — pure crypto, optional Rekor submission
	signRes, err := SignManifest(ctx, assembled.Digest.String(), opts.SigningKey, opts.KeyPassword, opts.Rekor)
	if err != nil {
		return nil, fmt.Errorf("pack: sign: %w", err)
	}

	// 5. Write OCI layout with all three manifests (filesystem I/O)
	if err := writeOCILayout(assembled.Image, sbomImage, signRes.Image, opts.OutputRoot, opts.OutputName, assembled.Digest.String()); err != nil {
		return nil, err
	}

	return &PackResult{Digest: lane.MustParseDigest(assembled.Digest.String()), Rekor: signRes.Rekor}, nil
}

// addFileLayers appends a layer for each file entry, returning the updated
// image and the host path of the first binary (used for SBOM generation).
// When the host path is a directory, a dirLayer is created instead of a
// fileLayer; the directory tree is mirrored at dest in the container image.
func addFileLayers(img v1.Image, files []lane.PackFile, inputPaths map[string]string) (v1.Image, string, error) {
	var binaryPath string
	for _, f := range files {
		dest := f.Dest.String()
		hostPath, ok := inputPaths[dest]
		if !ok {
			return nil, "", fmt.Errorf("pack: file dest %q: host path not resolved", dest)
		}
		info, err := os.Lstat(hostPath)
		if err != nil {
			return nil, "", fmt.Errorf("pack: stat %q: %w", dest, err)
		}
		var layer v1.Layer
		switch {
		case info.IsDir():
			layer, err = dirLayer(hostPath, dest)
		case info.Mode().IsRegular():
			if binaryPath == "" {
				binaryPath = hostPath
			}
			if f.Mode < 0 || f.Mode > 0o7777 {
				return nil, "", fmt.Errorf("pack: file %q: invalid mode %#o", dest, f.Mode)
			}
			layer, err = fileLayer(hostPath, dest, fs.FileMode(f.Mode))
		default:
			return nil, "", fmt.Errorf("pack: %q: unsupported file type %v", dest, info.Mode().Type())
		}
		if err != nil {
			return nil, "", fmt.Errorf("pack: add %q: %w", dest, err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			return nil, "", fmt.Errorf("pack: append layer: %w", err)
		}
	}
	return img, binaryPath, nil
}

// addConfigFileLayers appends a layer for each config file entry with literal content.
func addConfigFileLayers(img v1.Image, configFiles map[string]lane.FileEntry) (v1.Image, error) {
	if configFiles == nil {
		return img, nil
	}
	for path, entry := range configFiles {
		if entry.Mode < 0 || entry.Mode > 0o7777 {
			return nil, fmt.Errorf("pack: config file %q: invalid mode %#o", path, entry.Mode)
		}
		layer, cfErr := buildTarLayer(
			[]byte(entry.Content),
			path,
			fs.FileMode(entry.Mode),
			int(entry.UID),
			int(entry.GID),
		)
		if cfErr != nil {
			return nil, fmt.Errorf("pack: config file %q: %w", path, cfErr)
		}
		var err error
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			return nil, fmt.Errorf("pack: append config file layer: %w", err)
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
		for k, v := range spec.Config.Env {
			cfg.Config.Env = appendEnv(cfg.Config.Env, k, v)
		}
	}
	if spec.Config.Entrypoint != nil {
		cfg.Config.Entrypoint = spec.Config.Entrypoint
	}
	if spec.Config.Cmd != nil {
		cfg.Config.Cmd = spec.Config.Cmd
	}
	if spec.Config.Workdir != "" {
		cfg.Config.WorkingDir = spec.Config.Workdir
	}
	if spec.Config.User != "" {
		cfg.Config.User = spec.Config.User
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

// writeOCILayout writes the main image, SBOM, and signature to an OCI layout
// tar in the given output root.
func writeOCILayout(img, sbomImage, sigImage v1.Image, outputRoot *os.Root, outputName, imgDigest string) error {
	layoutDir, err := os.MkdirTemp("", "strike-pack-layout-")
	if err != nil {
		return fmt.Errorf("pack: temp dir: %w", err)
	}
	defer warnRemoveAll(layoutDir, "pack layout")

	lp, err := layout.Write(layoutDir, empty.Index)
	if err != nil {
		return fmt.Errorf("pack: write layout: %w", err)
	}
	if err := lp.AppendImage(img, layout.WithAnnotations(map[string]string{
		"org.opencontainers.image.ref.name": imgDigest,
	})); err != nil {
		return fmt.Errorf("pack: append main image: %w", err)
	}
	if err := lp.AppendImage(sbomImage); err != nil {
		return fmt.Errorf("pack: append SBOM: %w", err)
	}
	if err := lp.AppendImage(sigImage); err != nil {
		return fmt.Errorf("pack: append signature: %w", err)
	}

	if err := tarDirectoryToRoot(layoutDir, outputRoot, outputName); err != nil {
		return fmt.Errorf("pack: tar layout: %w", err)
	}
	return nil
}

// pullVerified pulls a remote image by digest-pinned reference.
// For multi-arch images the ref digest pins the index; go-containerregistry
// verifies the index digest on fetch, then resolves to the platform image.
func pullVerified(ref string) (v1.Image, error) {
	nameRef, err := name.ParseReference(ref)
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

// buildTarLayer creates a single-file OCI layer from in-memory content.
func buildTarLayer(content []byte, destPath string, mode fs.FileMode, uid, gid int) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, dir := range parentDirs(destPath) {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     dir + "/",
			Mode:     0o755,
		}); err != nil {
			return nil, err
		}
	}

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     destPath[1:], // strip leading /
		Size:     int64(len(content)),
		Mode:     int64(mode),
		Uid:      uid,
		Gid:      gid,
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	return tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
}

// fileLayer reads a file from disk and creates an OCI layer.
func fileLayer(hostPath, destPath string, mode fs.FileMode) (v1.Layer, error) {
	data, err := os.ReadFile(hostPath) //nolint:gosec // G304: absolute path from MkdirTemp output directory
	if err != nil {
		return nil, err
	}
	return buildTarLayer(data, destPath, mode, 0, 0)
}

// dirLayer reads a directory recursively and creates an OCI layer that
// mirrors the directory tree at destPath in the container. File modes
// are preserved; ownership is normalized to 0:0; mtimes are zeroed for
// determinism. Symlinks are rejected (pre-beta strict policy).
func dirLayer(hostDir, destPath string) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	dest := filepath.Clean(destPath[1:]) // strip leading /

	// Emit the root directory entry for dest.
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     dest + "/",
		Mode:     0o755,
	}); err != nil {
		return nil, err
	}

	if err := filepath.WalkDir(hostDir, dirWalkFunc(tw, hostDir, dest)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	return tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
}

// dirWalkFunc returns a WalkDir callback that writes each entry under
// root into a tar at the given dest prefix.
func dirWalkFunc(tw *tar.Writer, root, dest string) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink at %q: not supported", rel)
		}
		return writeDirEntry(tw, path, d, filepath.Join(dest, rel))
	}
}

// writeDirEntry writes a single directory or file entry to the tar writer.
func writeDirEntry(tw *tar.Writer, hostPath string, d fs.DirEntry, tarName string) error {
	info, err := d.Info()
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name: tarName,
		Mode: int64(info.Mode().Perm()),
		// Uid, Gid, ModTime intentionally zero for determinism.
	}
	switch {
	case d.IsDir():
		hdr.Typeflag = tar.TypeDir
		hdr.Name += "/"
	case info.Mode().IsRegular():
		hdr.Typeflag = tar.TypeReg
		hdr.Size = info.Size()
	default:
		return fmt.Errorf("unsupported file type %v at %q", info.Mode().Type(), tarName)
	}
	if err = tw.WriteHeader(hdr); err != nil {
		return err
	}
	if d.IsDir() {
		return nil
	}
	f, err := os.Open(hostPath) //nolint:gosec // G304: path from controlled WalkDir within MkdirTemp output
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // best-effort in walk callback
	_, err = io.Copy(tw, f)
	return err
}

// parentDirs returns all parent directory paths for an absolute path.
// e.g. "/usr/bin/strike" -> ["usr", "usr/bin"].
func parentDirs(absPath string) []string {
	clean := filepath.Clean(absPath[1:]) // strip leading /
	dir := filepath.Dir(clean)
	if dir == "." {
		return nil
	}
	var dirs []string
	for d := dir; d != "."; d = filepath.Dir(d) {
		dirs = append([]string{d}, dirs...)
	}
	return dirs
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

// artifactImage creates a single-layer OCI artifact image with subject
// descriptor for OCI 1.1 referrer relationship.
func artifactImage(content []byte, artifactType string, subject v1.Descriptor) (v1.Image, error) {
	layer := static.NewLayer(content, types.MediaType(artifactType))

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("unexpected type from mutate.Annotations")
	}
	img = annotated

	var err error
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, err
	}

	withSubject, ok := mutate.Subject(img, subject).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("unexpected type from mutate.Subject")
	}
	img = withSubject
	return img, nil
}

// tarDirectoryToRoot tars a directory and writes the output through root.
func tarDirectoryToRoot(srcDir string, outputRoot *os.Root, outputName string) (err error) {
	f, err := outputRoot.Create(outputName)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	tw := tar.NewWriter(f)
	defer func() {
		if cerr := tw.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	return filepath.WalkDir(srcDir, tarWalkFunc(srcDir, tw))
}

// tarWalkFunc returns a WalkDir callback that writes each entry to tw.
func tarWalkFunc(srcDir string, tw *tar.Writer) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(srcDir, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		return tarEntry(tw, path, rel, d)
	}
}

// tarEntry writes a single file or directory entry to the tar writer.
// path is an absolute path within a MkdirTemp layout directory.
func tarEntry(tw *tar.Writer, path, rel string, d fs.DirEntry) error {
	info, err := d.Info()
	if err != nil {
		return err
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = rel
	if err = tw.WriteHeader(header); err != nil {
		return err
	}
	if d.IsDir() {
		return nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: absolute path from MkdirTemp layout directory
	if err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}
