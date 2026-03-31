package executor

import (
	"archive/tar"
	"bytes"
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

	"github.com/istr/strike/lane"
)

// PackOpts is everything pack needs; callers in main.go assemble this.
type PackOpts struct {
	Spec        *lane.PackSpec
	InputPaths  map[string]string // "step_name.output_name" -> host path
	OutputPath  string            // path to write the oci-tar
	SigningKey  []byte            // PEM-encoded ECDSA P-256 private key
	KeyPassword []byte            // passphrase for encrypted key; empty if unencrypted
	State       *lane.State       // lane state for artifact provenance
}

// PackResult holds the outputs of a successful pack operation.
type PackResult struct {
	Digest string // "sha256:..." manifest digest of the main image
}

func Pack(opts PackOpts) (*PackResult, error) {
	if opts.SigningKey == nil {
		return nil, fmt.Errorf("pack: signing key is required; keyless signing is not yet implemented")
	}

	// 1. Pull and verify the base image
	img, err := pullVerified(string(opts.Spec.Base))
	if err != nil {
		return nil, fmt.Errorf("pack: pull base image: %w", err)
	}

	// Track the first binary path for SBOM generation
	var binaryPath string

	// 2. Add file layers
	for _, f := range opts.Spec.Files {
		hostPath, ok := opts.InputPaths[f.From]
		if !ok {
			return nil, fmt.Errorf("pack: file from %q: host path not resolved", f.From)
		}
		if binaryPath == "" {
			binaryPath = hostPath
		}
		layer, err := fileLayer(hostPath, f.Dest, fs.FileMode(f.Mode))
		if err != nil {
			return nil, fmt.Errorf("pack: add file %q: %w", f.Dest, err)
		}
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			return nil, fmt.Errorf("pack: append layer: %w", err)
		}
	}

	// 2b. Add config file layers (literal content)
	if opts.Spec.Config_files != nil {
		for path, entry := range opts.Spec.Config_files {
			layer, cfErr := fileLayerFromContent(
				[]byte(entry.Content),
				path,
				fs.FileMode(entry.Mode),
				int(entry.UID),
				int(entry.GID),
			)
			if cfErr != nil {
				return nil, fmt.Errorf("pack: config file %q: %w", path, cfErr)
			}
			img, err = mutate.AppendLayers(img, layer)
			if err != nil {
				return nil, fmt.Errorf("pack: append config file layer: %w", err)
			}
		}
	}

	// 3. Apply image configuration
	if opts.Spec.Config != nil {
		cfg, cfgErr := img.ConfigFile()
		if cfgErr != nil {
			return nil, fmt.Errorf("pack: read config: %w", cfgErr)
		}
		cfg = cfg.DeepCopy()

		if opts.Spec.Config.Env != nil {
			for k, v := range opts.Spec.Config.Env {
				cfg.Config.Env = appendEnv(cfg.Config.Env, k, v)
			}
		}
		if opts.Spec.Config.Entrypoint != nil {
			cfg.Config.Entrypoint = opts.Spec.Config.Entrypoint
		}
		if opts.Spec.Config.Cmd != nil {
			cfg.Config.Cmd = opts.Spec.Config.Cmd
		}
		if opts.Spec.Config.Workdir != "" {
			cfg.Config.WorkingDir = opts.Spec.Config.Workdir
		}
		if opts.Spec.Config.User != "" {
			cfg.Config.User = opts.Spec.Config.User
		}
		if opts.Spec.Config.Labels != nil {
			if cfg.Config.Labels == nil {
				cfg.Config.Labels = make(map[string]string)
			}
			for k, v := range opts.Spec.Config.Labels {
				cfg.Config.Labels[k] = v
			}
		}

		img, err = mutate.ConfigFile(img, cfg)
		if err != nil {
			return nil, fmt.Errorf("pack: apply config: %w", err)
		}
	}

	// 4. Apply annotations
	if opts.Spec.Annotations != nil {
		img = mutate.Annotations(img, opts.Spec.Annotations).(v1.Image)
	}

	// Compute image digest for referrer relationships
	imgDigest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("pack: image digest: %w", err)
	}
	imgSize, err := img.Size()
	if err != nil {
		return nil, fmt.Errorf("pack: image size: %w", err)
	}
	imgMediaType, err := img.MediaType()
	if err != nil {
		return nil, fmt.Errorf("pack: image media type: %w", err)
	}
	subject := v1.Descriptor{
		MediaType: imgMediaType,
		Digest:    imgDigest,
		Size:      imgSize,
	}

	// 3. Generate SBOM
	sbomBytes, err := GenerateSBOM(binaryPath, imgDigest.String(), string(opts.Spec.Base))
	if err != nil {
		return nil, fmt.Errorf("pack: sbom: %w", err)
	}
	sbomImage, err := artifactImage(sbomBytes, "application/vnd.cyclonedx+json", subject)
	if err != nil {
		return nil, fmt.Errorf("pack: SBOM artifact: %w", err)
	}

	// 4. Sign the image manifest digest
	sigImage, err := SignManifest(imgDigest.String(), opts.SigningKey, opts.KeyPassword)
	if err != nil {
		return nil, fmt.Errorf("pack: sign: %w", err)
	}

	// 5. Write OCI layout with all three manifests
	layoutDir, err := os.MkdirTemp("", "strike-pack-layout-")
	if err != nil {
		return nil, fmt.Errorf("pack: temp dir: %w", err)
	}
	defer os.RemoveAll(layoutDir)

	lp, err := layout.Write(layoutDir, empty.Index)
	if err != nil {
		return nil, fmt.Errorf("pack: write layout: %w", err)
	}
	if err := lp.AppendImage(img, layout.WithAnnotations(map[string]string{
		"org.opencontainers.image.ref.name": imgDigest.String(),
	})); err != nil {
		return nil, fmt.Errorf("pack: append main image: %w", err)
	}
	if err := lp.AppendImage(sbomImage); err != nil {
		return nil, fmt.Errorf("pack: append SBOM: %w", err)
	}
	if err := lp.AppendImage(sigImage); err != nil {
		return nil, fmt.Errorf("pack: append signature: %w", err)
	}

	// 6. Tar the OCI layout to the output path
	if err := tarDirectory(layoutDir, opts.OutputPath); err != nil {
		return nil, fmt.Errorf("pack: tar layout: %w", err)
	}

	return &PackResult{Digest: imgDigest.String()}, nil
}

// pullVerified pulls a remote image by digest-pinned reference.
// For multi-arch images the ref digest pins the index; go-containerregistry
// verifies the index digest on fetch, then resolves to the platform image.
func pullVerified(ref string) (v1.Image, error) {
	nameRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse ref %q: %w", ref, err)
	}

	// Require a digest reference — tags are not allowed.
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

// fileLayer creates a single-file OCI layer as a tar archive.
func fileLayer(hostPath, destPath string, mode fs.FileMode) (v1.Layer, error) {
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add parent directories
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
		Size:     int64(len(data)),
		Mode:     int64(mode),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
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

// parentDirs returns all parent directory paths for an absolute path.
// e.g. "/usr/bin/strike" -> ["usr", "usr/bin"]
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

// fileLayerFromContent creates a single-file OCI layer from in-memory content.
func fileLayerFromContent(content []byte, destPath string, mode fs.FileMode, uid, gid int) (v1.Layer, error) {
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
	img = mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)

	var err error
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, err
	}

	img = mutate.Subject(img, subject).(v1.Image)
	return img, nil
}

// tarDirectory tars a directory to the given output path.
func tarDirectory(srcDir, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
}
