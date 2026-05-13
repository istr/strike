package registry

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
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/lane"
)

// WrapFileAsImage packages a single file into an OCI image, loads it into
// the engine's local store, tags it, and returns the manifest digest.
// The file is placed at its base name inside the image. Symlinks are rejected.
func (c *Client) WrapFileAsImage(ctx context.Context, srcPath, tag string) (lane.Digest, error) {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap file: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return lane.Digest{}, fmt.Errorf("wrap file: symlink not allowed: %s", srcPath)
	}
	if !info.Mode().IsRegular() {
		return lane.Digest{}, fmt.Errorf("wrap file: not a regular file: %s", srcPath)
	}

	destPath := "/" + filepath.Base(srcPath)
	layer, err := wrapFileLayer(srcPath, destPath, info.Mode().Perm())
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap file layer: %w", err)
	}

	return c.loadTagInspect(ctx, layer, tag)
}

// WrapDirectoryAsImage packages a directory tree into an OCI image, loads it
// into the engine's local store, tags it, and returns the manifest digest.
// The directory contents are placed under its base name inside the image.
// Symlinks within the directory are rejected.
func (c *Client) WrapDirectoryAsImage(ctx context.Context, srcPath, tag string) (lane.Digest, error) {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap dir: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return lane.Digest{}, fmt.Errorf("wrap dir: symlink not allowed: %s", srcPath)
	}
	if !info.IsDir() {
		return lane.Digest{}, fmt.Errorf("wrap dir: not a directory: %s", srcPath)
	}

	destPath := "/" + filepath.Base(srcPath)
	layer, err := wrapDirLayer(srcPath, destPath)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap dir layer: %w", err)
	}

	return c.loadTagInspect(ctx, layer, tag)
}

// WrapImageOutputAsImage loads an existing OCI tar into the engine's local
// store, tags it, and returns the manifest digest.
func (c *Client) WrapImageOutputAsImage(ctx context.Context, tarPath, tag string) (lane.Digest, error) {
	f, err := os.Open(tarPath) //nolint:gosec // G304: tarPath is from MkdirTemp output directory
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap image: %w", err)
	}
	defer warnClose(f, "wrap image")

	r, err := openMainImageFromReader(f)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap image: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, r)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("wrap image load: %w", err)
	}

	if err := c.Engine.ImageTag(ctx, id, tag); err != nil {
		return lane.Digest{}, fmt.Errorf("wrap image tag: %w", err)
	}

	return c.InspectDigest(ctx, tag)
}

// loadTagInspect builds a single-layer OCI image from the given layer,
// loads it into the engine, tags it, and returns the manifest digest.
func (c *Client) loadTagInspect(ctx context.Context, layer v1.Layer, tag string) (lane.Digest, error) {
	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)

	img, err := mutate.AppendLayers(img, layer)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("append layer: %w", err)
	}

	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return lane.Digest{}, fmt.Errorf("annotate image: unexpected type")
	}
	img = annotated

	r, err := singleImageTar(img, nil)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("write image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, r)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("image load: %w", err)
	}

	if err := c.Engine.ImageTag(ctx, id, tag); err != nil {
		return lane.Digest{}, fmt.Errorf("image tag: %w", err)
	}

	return c.InspectDigest(ctx, tag)
}

// openMainImageFromReader reads an OCI layout tar from r and returns a
// reader for a single-image OCI tar suitable for engine load.
func openMainImageFromReader(r io.Reader) (io.Reader, error) {
	tmpDir, err := os.MkdirTemp("", "strike-wrap-load-")
	if err != nil {
		return nil, err
	}
	defer warnRemoveAll(tmpDir, "wrap image load")

	if extractErr := extractTar(r, tmpDir); extractErr != nil {
		return nil, fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("empty image index")
	}

	desc := manifest.Manifests[0]
	img, err := idx.Image(desc.Digest)
	if err != nil {
		return nil, err
	}
	return singleImageTar(img, desc.Annotations)
}

// wrapFileLayer reads a file from disk and creates a deterministic OCI layer.
// Ownership is normalized to 0:0; mtime is zeroed for reproducibility.
func wrapFileLayer(hostPath, destPath string, mode fs.FileMode) (v1.Layer, error) {
	data, err := os.ReadFile(hostPath) //nolint:gosec // G304: hostPath is from MkdirTemp output directory
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     destPath[1:], // strip leading /
		Size:     int64(len(data)),
		Mode:     int64(mode),
		// Uid, Gid, ModTime intentionally zero for determinism.
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

// wrapDirLayer reads a directory recursively and creates a deterministic OCI
// layer. File modes are preserved; ownership is normalized to 0:0; mtimes
// are zeroed. Symlinks are rejected.
func wrapDirLayer(hostDir, destPath string) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	dest := filepath.Clean(destPath[1:]) // strip leading /

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     dest + "/",
		Mode:     0o755,
	}); err != nil {
		return nil, err
	}

	if err := filepath.WalkDir(hostDir, wrapDirWalkFunc(tw, hostDir, dest)); err != nil {
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

// wrapDirWalkFunc returns a WalkDir callback that writes each entry under
// root into a tar at the given dest prefix.
func wrapDirWalkFunc(tw *tar.Writer, root, dest string) fs.WalkDirFunc {
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

		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		hdr := &tar.Header{
			Name: filepath.Join(dest, rel),
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
			return fmt.Errorf("unsupported file type %v at %q", info.Mode().Type(), rel)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // G304: path from controlled WalkDir within MkdirTemp output
		if err != nil {
			return err
		}
		defer warnClose(f, "wrap dir layer")
		_, err = io.Copy(tw, f)
		return err
	}
}
