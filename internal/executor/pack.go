// Package executor implements container execution, OCI image assembly,
// and SBOM generation for strike lane steps.
package executor

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/istr/strike/internal/closer"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
)

// PackOpts is everything pack needs; callers in main.go assemble this.
type PackOpts struct {
	InputPaths map[string]string
	Spec       *lane.PackSpec
	OutputRoot *os.Root // root-scoped output directory
	OutputName string   // filename within OutputRoot
}

// PackResult holds the outputs of a successful pack operation.
type PackResult struct {
	Digest primitive.Digest // "sha256:..." manifest digest of the main image
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
// and annotations -- no network I/O, no filesystem writes.
//
// This function defines the cross-validation surface for a Rust verifier:
// given identical (base, spec, inputPaths), the output Digest must match.
func AssembleImage(base v1.Image, spec *lane.PackSpec, inputPaths map[string]string) (*AssembleResult, error) {
	// 1. Add file layers
	img, err := addFileLayers(base, spec.Files, inputPaths)
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

// Pack assembles an OCI image from the given options, generates an SBOM,
// and writes the result as an OCI layout tar.
//
// Pack is the orchestrator: it handles I/O (pull, write) and delegates
// to pure functions (AssembleImage, GenerateImageSBOM) for the
// security-critical computations.
func Pack(opts PackOpts) (*PackResult, error) {
	// 1. Pull and verify the base image (network I/O)
	base, err := pullVerified(opts.Spec.Base)
	if err != nil {
		return nil, fmt.Errorf("pack: pull base image: %w", err)
	}

	// 2. Assemble image -- pure computation, no I/O
	assembled, err := AssembleImage(base, opts.Spec, opts.InputPaths)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	// 3. Catalog the assembled image filesystem in-process (sealed, layer V):
	// flatten the image to an fs.FS and emit both CycloneDX and SPDX 2.3 bound
	// to the artifact's digest. No registry probe and no base-SBOM fetch --
	// verified base-SBOM ingestion against base_sbom_signers is a later
	// instruction. An empty catalog is surfaced as INFO inside the cataloger.
	buildTime := clock.Reproducible()
	imageFS, err := flattenImageToFS(assembled.Image)
	if err != nil {
		return nil, fmt.Errorf("pack: flatten image: %w", err)
	}
	cdxBytes, spdxBytes, err := GenerateImageSBOM(imageFS, assembled.Digest.String(), buildTime)
	if err != nil {
		return nil, fmt.Errorf("pack: sbom: %w", err)
	}
	cdxImage, err := registry.ArtifactImage(cdxBytes, "application/vnd.cyclonedx+json", assembled.Subject)
	if err != nil {
		return nil, fmt.Errorf("pack: cyclonedx artifact: %w", err)
	}
	spdxImage, err := registry.ArtifactImage(spdxBytes, "application/spdx+json", assembled.Subject)
	if err != nil {
		return nil, fmt.Errorf("pack: spdx artifact: %w", err)
	}

	// 4. Write OCI layout (filesystem I/O).
	if err := writeOCILayout(assembled.Image, []v1.Image{cdxImage, spdxImage}, opts.OutputRoot, opts.OutputName, assembled.Digest.String()); err != nil {
		return nil, err
	}

	manifestDigest := primitive.Digest(assembled.Digest.String())
	return &PackResult{Digest: manifestDigest}, nil
}

// addFileLayers appends a layer for each file entry, returning the updated
// image. When the host path is a directory, a dirLayer is created instead of
// a fileLayer; the directory tree is mirrored at dest in the container image.
func addFileLayers(img v1.Image, files []lane.PackFile, inputPaths map[string]string) (v1.Image, error) {
	for _, f := range files {
		dest := f.Dest.String()
		hostPath, ok := inputPaths[dest]
		if !ok {
			return nil, fmt.Errorf("pack: file dest %q: host path not resolved", dest)
		}
		info, err := os.Lstat(hostPath)
		if err != nil {
			return nil, fmt.Errorf("pack: stat %q: %w", dest, err)
		}
		switch {
		case info.IsDir():
			img, err = appendDirLayer(img, hostPath, dest)
		case info.Mode().IsRegular():
			img, err = appendRegularFileLayer(img, hostPath, dest, f.Mode)
		default:
			return nil, fmt.Errorf("pack: %q: unsupported file type %v", dest, info.Mode().Type())
		}
		if err != nil {
			return nil, fmt.Errorf("pack: %w", err)
		}
	}
	return img, nil
}

// appendDirLayer creates a directory layer from hostPath and appends it to img.
func appendDirLayer(img v1.Image, hostPath, dest string) (v1.Image, error) {
	dirRoot, err := os.OpenRoot(hostPath)
	if err != nil {
		return nil, fmt.Errorf("open dir %q: %w", dest, err)
	}
	layer, layerErr := dirLayer(dirRoot, dest)
	closer.Warn(dirRoot, "pack dir root")
	if layerErr != nil {
		return nil, fmt.Errorf("add %q: %w", dest, layerErr)
	}
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, fmt.Errorf("append layer: %w", err)
	}
	return img, nil
}

// appendRegularFileLayer creates a single-file layer and appends it to img.
func appendRegularFileLayer(img v1.Image, hostPath, dest string, mode int64) (v1.Image, error) {
	if mode < 0 || mode > 0o7777 {
		return nil, fmt.Errorf("file %q: invalid mode %#o", dest, mode)
	}
	fileRoot, err := os.OpenRoot(filepath.Dir(hostPath))
	if err != nil {
		return nil, fmt.Errorf("open file dir %q: %w", dest, err)
	}
	layer, layerErr := fileLayer(fileRoot, filepath.Base(hostPath), dest, fs.FileMode(mode))
	closer.Warn(fileRoot, "pack file root")
	if layerErr != nil {
		return nil, fmt.Errorf("add %q: %w", dest, layerErr)
	}
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, fmt.Errorf("append layer: %w", err)
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

// writeOCILayout writes the main image and SBOM to an OCI layout
// tar in the given output root.
func writeOCILayout(img v1.Image, sbomImages []v1.Image, outputRoot *os.Root, outputID, imgDigest string) error {
	layoutDir, err := os.MkdirTemp("", "strike-pack-layout-")
	if err != nil {
		return fmt.Errorf("pack: temp dir: %w", err)
	}
	defer closer.Remove(layoutDir, "pack layout")

	lp, err := layout.Write(layoutDir, empty.Index)
	if err != nil {
		return fmt.Errorf("pack: write layout: %w", err)
	}
	if err := lp.AppendImage(img, layout.WithAnnotations(map[string]string{
		"org.opencontainers.image.ref.name": imgDigest,
	})); err != nil {
		return fmt.Errorf("pack: append main image: %w", err)
	}
	for _, si := range sbomImages {
		if err := lp.AppendImage(si); err != nil {
			return fmt.Errorf("pack: append SBOM: %w", err)
		}
	}

	if err := tarDirectoryToRoot(layoutDir, outputRoot, outputID); err != nil {
		return fmt.Errorf("pack: tar layout: %w", err)
	}
	return nil
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

// fileLayer reads a file from a root-scoped directory and creates an OCI layer.
func fileLayer(root *os.Root, name, destPath string, mode fs.FileMode) (v1.Layer, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	closer.Warn(f, "pack file layer")
	if err != nil {
		return nil, err
	}
	return buildTarLayer(data, destPath, mode, 0, 0)
}

// dirLayer reads a directory recursively via *os.Root and creates an OCI layer
// that mirrors the directory tree at destPath in the container. File modes
// are preserved; ownership is normalized to 0:0; mtimes are zeroed for
// determinism. Symlinks are rejected (pre-beta strict policy).
func dirLayer(root *os.Root, destPath string) (v1.Layer, error) {
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

	if err := fs.WalkDir(root.FS(), ".", dirWalkFunc(root, tw, dest)); err != nil {
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
func dirWalkFunc(root *os.Root, tw *tar.Writer, dest string) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, linkErr := root.Readlink(path)
			if linkErr != nil {
				return fmt.Errorf("read symlink %q: %w", path, linkErr)
			}
			if lane.SymlinkEscapes(path, target) {
				return fmt.Errorf("symlink %q escapes packed tree (target %q)", path, target)
			}
			return tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeSymlink,
				Name:     filepath.Join(dest, path),
				Linkname: target,
				Mode:     0o777,
				// Uid, Gid, ModTime intentionally zero for determinism.
			})
		}
		return writeDirEntry(tw, root, path, d, filepath.Join(dest, path))
	}
}

// writeDirEntry writes a single directory or file entry to the tar writer.
func writeDirEntry(tw *tar.Writer, root *os.Root, relPath string, d fs.DirEntry, tarName string) error {
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
	f, err := root.Open(relPath)
	if err != nil {
		return err
	}
	defer closer.Warn(f, "pack walk file")
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

// tarDirectoryToRoot tars a directory and writes the output through outputRoot.
func tarDirectoryToRoot(srcDir string, outputRoot *os.Root, outputID string) (err error) {
	f, err := outputRoot.Create(outputID)
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

	srcRoot, rootErr := os.OpenRoot(srcDir)
	if rootErr != nil {
		return rootErr
	}
	defer closer.Warn(srcRoot, "pack tar source root")

	return fs.WalkDir(srcRoot.FS(), ".", tarWalkFunc(srcRoot, tw))
}

// tarWalkFunc returns a WalkDir callback that writes each entry to tw.
func tarWalkFunc(root *os.Root, tw *tar.Writer) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		return tarEntry(tw, root, path, d)
	}
}

// tarEntry writes a single file or directory entry to the tar writer.
func tarEntry(tw *tar.Writer, root *os.Root, rel string, d fs.DirEntry) error {
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
	f, openErr := root.Open(rel)
	if openErr != nil {
		return openErr
	}
	_, cpErr := io.Copy(tw, f)
	closer.Warn(f, "pack tar entry")
	return cpErr
}
