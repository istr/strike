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
	"strconv"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/lane"
)

// ContentSizeAnnotation is the OCI annotation key that stores the logical
// content size (in bytes) of the wrapped artifact. Written by wrapOutputs,
// read by the cache-hit path to restore Artifact.Size without re-extraction.
const ContentSizeAnnotation = "dev.strike.content-size"

// SignedAnnotation is the OCI annotation key that records whether a pack
// step signed this artifact. Written by executePack, read by the cache-hit
// path to restore Artifact.Signed without re-inspection.
const SignedAnnotation = "dev.strike.signed"

// WrapFileAsImage packages a single file into an OCI image, loads it into
// the engine's local store, tags it, and returns the manifest digest and
// logical byte size. Symlinks are rejected. root is the output directory;
// name is the relative file path within it.
func (c *Client) WrapFileAsImage(ctx context.Context, root *os.Root, name, tag string) (lane.Digest, int64, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap file: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return lane.Digest{}, 0, fmt.Errorf("wrap file: symlink not allowed: %s", name)
	}
	if !info.Mode().IsRegular() {
		return lane.Digest{}, 0, fmt.Errorf("wrap file: not a regular file: %s", name)
	}

	destPath := "/" + name
	layer, size, err := wrapFileLayer(root, name, destPath, info.Mode().Perm())
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap file layer: %w", err)
	}

	digest, err := c.loadTagVerify(ctx, layer, tag, size)
	if err != nil {
		return lane.Digest{}, 0, err
	}
	return digest, size, nil
}

// WrapDirectoryAsImage packages a directory tree into an OCI image, loads it
// into the engine's local store, tags it, and returns the manifest digest and
// logical byte size (sum of regular file content sizes). Symlinks are rejected.
// root is the output directory; name is the relative directory path within it.
func (c *Client) WrapDirectoryAsImage(ctx context.Context, root *os.Root, name, tag string) (lane.Digest, int64, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap dir: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return lane.Digest{}, 0, fmt.Errorf("wrap dir: symlink not allowed: %s", name)
	}
	if !info.IsDir() {
		return lane.Digest{}, 0, fmt.Errorf("wrap dir: not a directory: %s", name)
	}

	destPath := "/" + name
	layer, size, err := wrapDirLayer(root, name, destPath)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap dir layer: %w", err)
	}

	digest, err := c.loadTagVerify(ctx, layer, tag, size)
	if err != nil {
		return lane.Digest{}, 0, err
	}
	return digest, size, nil
}

// WrapImageOutputAsImage loads an existing OCI tar into the engine's local
// store, tags it, and returns the manifest digest and the tar file size.
// The controller-computed manifest digest is verified against the engine.
// root is the output directory; name is the relative tar path within it.
// Optional extra annotations are merged into the manifest alongside the
// standard created and content-size annotations.
func (c *Client) WrapImageOutputAsImage(ctx context.Context, root *os.Root, name, tag string, extra ...map[string]string) (lane.Digest, int64, error) {
	info, err := root.Stat(name)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image stat: %w", err)
	}
	size := info.Size()

	f, err := root.Open(name)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: %w", err)
	}
	defer closer.Warn(f, "wrap image")

	return c.wrapImageFromReader(ctx, f, size, tag, extra...)
}

// wrapImageFromReader loads an OCI-layout tar from r (size bytes), annotates
// it, loads it into the engine, tags it, and verifies the controller digest
// against the engine. Shared by WrapImageOutputAsImage (host file) and
// WrapImageArchiveAsImage (engine archive stream).
func (c *Client) wrapImageFromReader(ctx context.Context, r io.Reader, size int64, tag string, extra ...map[string]string) (lane.Digest, int64, error) {
	img, cleanup, err := extractMainImage(r)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: %w", err)
	}
	defer cleanup()

	ann := map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
		ContentSizeAnnotation:              strconv.FormatInt(size, 10),
	}
	for _, m := range extra {
		for k, v := range m {
			ann[k] = v
		}
	}
	annotated, ok := mutate.Annotations(img, ann).(v1.Image)
	if !ok {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: annotate: unexpected type")
	}
	img = annotated

	expectedDigest, err := img.Digest()
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image digest: %w", err)
	}

	tarReader, err := singleImageTar(img, nil)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, tarReader)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image load: %w", err)
	}

	if tagErr := c.Engine.ImageTag(ctx, id, tag); tagErr != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image tag: %w", tagErr)
	}

	engineDigest, err := c.InspectDigest(ctx, tag)
	if err != nil {
		return lane.Digest{}, 0, fmt.Errorf("wrap image inspect: %w", err)
	}

	controllerDigest := v1HashToDigest(expectedDigest)
	if engineDigest != controllerDigest {
		return lane.Digest{}, 0, fmt.Errorf("wrap image: digest mismatch: controller=%s engine=%s", controllerDigest, engineDigest)
	}
	return engineDigest, size, nil
}

// loadTagVerify builds a single-layer OCI image from the given layer,
// loads it into the engine, tags it, and returns the manifest digest.
// The controller-computed manifest digest is verified against the engine.
// size is the logical content size written as the dev.strike.content-size
// annotation for cache-hit restoration.
func (c *Client) loadTagVerify(ctx context.Context, layer v1.Layer, tag string, size int64) (lane.Digest, error) {
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
		ContentSizeAnnotation:              strconv.FormatInt(size, 10),
	}).(v1.Image)
	if !ok {
		return lane.Digest{}, fmt.Errorf("annotate image: unexpected type")
	}
	img = annotated

	expectedHash, err := img.Digest()
	if err != nil {
		return lane.Digest{}, fmt.Errorf("compute digest: %w", err)
	}

	r, err := singleImageTar(img, nil)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("write image tar: %w", err)
	}

	id, err := c.Engine.ImageLoad(ctx, r)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("image load: %w", err)
	}

	if tagErr := c.Engine.ImageTag(ctx, id, tag); tagErr != nil {
		return lane.Digest{}, fmt.Errorf("image tag: %w", tagErr)
	}

	engineDigest, err := c.InspectDigest(ctx, tag)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("inspect digest: %w", err)
	}

	controllerDigest := v1HashToDigest(expectedHash)
	if engineDigest != controllerDigest {
		return lane.Digest{}, fmt.Errorf("digest mismatch: controller=%s engine=%s", controllerDigest, engineDigest)
	}
	return engineDigest, nil
}

// v1HashToDigest converts a go-containerregistry v1.Hash to a lane.Digest.
func v1HashToDigest(h v1.Hash) lane.Digest {
	return lane.Digest{Algorithm: h.Algorithm, Hex: h.Hex}
}

// extractMainImage reads an OCI layout tar from r and returns the first
// image from the index. The returned cleanup function removes the temporary
// directory backing the layout and must be called after the image is no
// longer needed.
func extractMainImage(r io.Reader) (v1.Image, func(), error) {
	tmpDir, err := os.MkdirTemp("", "strike-wrap-load-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { closer.Remove(tmpDir, "wrap image load") }

	tmpRoot, rootErr := os.OpenRoot(tmpDir)
	if rootErr != nil {
		cleanup()
		return nil, nil, rootErr
	}
	defer closer.Warn(tmpRoot, "wrap image load root")

	if extractErr := extractTar(r, tmpRoot); extractErr != nil {
		cleanup()
		return nil, nil, fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read manifest: %w", err)
	}

	if len(manifest.Manifests) == 0 {
		cleanup()
		return nil, nil, fmt.Errorf("empty image index")
	}

	desc := manifest.Manifests[0]
	img, imgErr := idx.Image(desc.Digest)
	if imgErr != nil {
		cleanup()
		return nil, nil, imgErr
	}
	return img, cleanup, nil
}

// wrapFileLayer reads a file from a root-scoped directory and creates a
// deterministic OCI layer. Returns the layer and the logical byte size of
// the file content. Ownership is normalized to 0:0; mtime is zeroed for
// reproducibility.
func wrapFileLayer(root *os.Root, name, destPath string, mode fs.FileMode) (v1.Layer, int64, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(f)
	closer.Warn(f, "wrap file layer read")
	if err != nil {
		return nil, 0, err
	}
	size := int64(len(data))

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err = tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     destPath[1:], // strip leading /
		Size:     size,
		Mode:     int64(mode),
		// Uid, Gid, ModTime intentionally zero for determinism.
	})
	if err != nil {
		return nil, 0, err
	}
	if _, writeErr := tw.Write(data); writeErr != nil {
		return nil, 0, writeErr
	}
	if closeErr := tw.Close(); closeErr != nil {
		return nil, 0, closeErr
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	layer, err := tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		return nil, 0, err
	}
	return layer, size, nil
}

// wrapDirLayer reads a directory recursively via *os.Root and creates a
// deterministic OCI layer. Returns the layer and the logical byte size (sum
// of regular file content sizes). File modes are preserved; ownership is
// normalized to 0:0; mtimes are zeroed. Symlinks are rejected.
func wrapDirLayer(root *os.Root, dirName, destPath string) (v1.Layer, int64, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	dest := filepath.Clean(destPath[1:]) // strip leading /

	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     dest + "/",
		Mode:     0o755,
	}); err != nil {
		return nil, 0, err
	}

	var totalSize int64
	if err := fs.WalkDir(root.FS(), dirName, wrapDirWalkFunc(root, tw, dirName, dest, &totalSize)); err != nil {
		return nil, 0, err
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	layer, err := tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		return nil, 0, err
	}
	return layer, totalSize, nil
}

// wrapSymlinkEntry validates containment and writes a symlink tar header.
func wrapSymlinkEntry(root *os.Root, tw *tar.Writer, path, rel, dest string) error {
	target, err := root.Readlink(path)
	if err != nil {
		return fmt.Errorf("read symlink %q: %w", rel, err)
	}
	if lane.SymlinkEscapes(rel, target) {
		return fmt.Errorf("symlink %q escapes output tree (target %q)", rel, target)
	}
	return tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     filepath.Join(dest, rel),
		Linkname: target,
		Mode:     0o777,
		// Uid, Gid, ModTime intentionally zero for determinism.
	})
}

// wrapDirWalkFunc returns a WalkDir callback that writes each entry under
// dirName into a tar at the given dest prefix. totalSize accumulates the
// logical byte count of regular file contents.
func wrapDirWalkFunc(root *os.Root, tw *tar.Writer, dirName, dest string, totalSize *int64) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(dirName, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return wrapSymlinkEntry(root, tw, path, rel, dest)
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
			*totalSize += info.Size()
		default:
			return fmt.Errorf("unsupported file type %v at %q", info.Mode().Type(), rel)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := root.Open(path)
		if err != nil {
			return err
		}
		defer closer.Warn(f, "wrap dir layer")
		_, err = io.Copy(tw, f)
		return err
	}
}
