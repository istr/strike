package registry

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/istr/strike/internal/closer"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
)

// Client wraps container engine operations for registry interaction.
type Client struct {
	Engine container.Engine
}

// PushArtifact pushes a local image to the registry.
func (c *Client) PushArtifact(ctx context.Context, tag string) error {
	return c.Engine.ImagePush(ctx, tag)
}

// CopyImage copies an image between registries using go-containerregistry.
func CopyImage(src, dst string) error {
	if err := crane.Copy(src, dst,
		crane.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return nil
}

// singleImageTar writes a single OCI image as a layout tar into an in-memory
// buffer and returns a reader over it.
func singleImageTar(img v1.Image, annotations map[string]string) (io.Reader, error) {
	tmpDir, err := os.MkdirTemp("", "strike-single-")
	if err != nil {
		return nil, err
	}
	defer closer.Remove(tmpDir, "registry single image")

	lp, err := layout.Write(tmpDir, empty.Index)
	if err != nil {
		return nil, fmt.Errorf("write single layout: %w", err)
	}
	var opts []layout.Option
	if len(annotations) > 0 {
		opts = append(opts, layout.WithAnnotations(annotations))
	}
	if err := lp.AppendImage(img, opts...); err != nil {
		return nil, fmt.Errorf("append image: %w", err)
	}

	var buf bytes.Buffer
	if err := tarDirectory(tmpDir, &buf); err != nil {
		return nil, fmt.Errorf("tar single layout: %w", err)
	}
	return &buf, nil
}

// extractTar extracts a tar archive into the given root-scoped directory.
func extractTar(r io.Reader, root *os.Root) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if mkErr := mkdirAllRoot(root, hdr.Name); mkErr != nil {
				return mkErr
			}
		case tar.TypeReg:
			if writeErr := extractFile(tr, root, hdr.Name); writeErr != nil {
				return writeErr
			}
		}
	}
}

// extractFile writes a single tar entry to the root-scoped filesystem.
func extractFile(tr *tar.Reader, root *os.Root, name string) error {
	if idx := strings.LastIndex(name, "/"); idx > 0 {
		if mkErr := mkdirAllRoot(root, name[:idx]); mkErr != nil {
			return mkErr
		}
	}
	out, err := root.Create(name)
	if err != nil {
		return err
	}
	if _, cpErr := io.Copy(out, tr); cpErr != nil {
		closer.Warn(out, "registry extract file")
		return cpErr
	}
	return out.Close()
}

// mkdirAllRoot creates a directory and all parents within the root scope.
func mkdirAllRoot(root *os.Root, path string) error {
	parts := strings.Split(strings.TrimRight(path, "/"), "/")
	cur := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if cur == "" {
			cur = p
		} else {
			cur = cur + "/" + p
		}
		if err := root.Mkdir(cur, 0o750); err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

// tarDirectory writes the contents of dir as a tar archive to w.
func tarDirectory(dir string, w io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer closer.Warn(root, "registry tar root")

	tw := tar.NewWriter(w)
	defer closer.Warn(tw, "registry tar")

	entries, rdErr := fs.ReadDir(root.FS(), ".")
	if rdErr != nil {
		return rdErr
	}
	return tarDirEntries(tw, root, "", entries)
}

// tarDirEntries recursively writes directory entries to a tar writer.
func tarDirEntries(tw *tar.Writer, root *os.Root, prefix string, entries []fs.DirEntry) error {
	for _, e := range entries {
		rel := prefix + e.Name()
		info, infoErr := e.Info()
		if infoErr != nil {
			return infoErr
		}
		hdr, hdrErr := tar.FileInfoHeader(info, "")
		if hdrErr != nil {
			return hdrErr
		}
		hdr.Name = rel
		if twErr := tw.WriteHeader(hdr); twErr != nil {
			return twErr
		}
		if e.IsDir() {
			sub, rdErr := fs.ReadDir(root.FS(), rel)
			if rdErr != nil {
				return rdErr
			}
			if err := tarDirEntries(tw, root, rel+"/", sub); err != nil {
				return err
			}
			continue
		}
		f, openErr := root.Open(rel)
		if openErr != nil {
			return openErr
		}
		_, cpErr := io.Copy(tw, f)
		closer.Warn(f, "registry tar entry")
		if cpErr != nil {
			return cpErr
		}
	}
	return nil
}

// InspectDigest returns the manifest digest of a local image.
func (c *Client) InspectDigest(ctx context.Context, ref string) (lane.Digest, error) {
	info, err := c.Engine.ImageInspect(ctx, ref)
	if err != nil {
		return lane.Digest{}, err
	}
	if info.Digest == "" {
		return lane.Digest{}, fmt.Errorf("no digest for %s", ref)
	}
	return lane.MustParseDigest(info.Digest), nil
}
