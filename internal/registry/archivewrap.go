package registry

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// canonicalEntry is a collected tar entry, held until all entries are read
// so they can be emitted in canonical (name-sorted) order. The engine
// archive's entry order is not guaranteed, so sorting is required for a
// reproducible layer.
type canonicalEntry struct {
	name     string // re-rooted name, no trailing slash
	linkname string // symlink target, verbatim (TypeSymlink only)
	content  []byte // regular-file content (TypeReg only)
	mode     int64
	typeflag byte
}

// canonicalLayerFromTar reads a tar stream and builds a deterministic OCI
// layer. Each entry's name has stripPrefix removed and destPrefix
// prepended. Ownership and mtime are zeroed; entries are sorted by name.
// Directories, regular files, and symlinks are supported; any other type
// is an error. A symlink whose target escapes the archived subtree
// (lane.SymlinkEscapes) is rejected; a contained one is stored verbatim.
func canonicalLayerFromTar(r io.Reader, stripPrefix, destPrefix string) (v1.Layer, int64, error) {
	entries, totalSize, err := collectArchiveEntries(r, stripPrefix, destPrefix)
	if err != nil {
		return nil, 0, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	buf, err := writeCanonicalTar(entries)
	if err != nil {
		return nil, 0, err
	}

	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	layer, err := tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		return nil, 0, err
	}
	return layer, totalSize, nil
}

// collectArchiveEntries reads all entries from a tar stream, strips the
// prefix, re-roots under destPrefix, validates symlinks, and returns the
// collected entries with the total regular-file content size.
func collectArchiveEntries(r io.Reader, stripPrefix, destPrefix string) ([]canonicalEntry, int64, error) {
	var (
		entries   []canonicalEntry
		totalSize int64
	)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read archive: %w", err)
		}

		rel, ok := relUnderPrefix(hdr.Name, stripPrefix)
		if !ok || rel == "" || rel == "." {
			continue // outside the subtree, or the subtree root itself
		}
		name := path.Join(destPrefix, rel)
		mode := int64(hdr.FileInfo().Mode().Perm())

		switch hdr.Typeflag {
		case tar.TypeDir:
			entries = append(entries, canonicalEntry{name: name, mode: mode, typeflag: tar.TypeDir})
		case tar.TypeReg:
			data, readErr := io.ReadAll(tr)
			if readErr != nil {
				return nil, 0, fmt.Errorf("read %q: %w", rel, readErr)
			}
			entries = append(entries, canonicalEntry{name: name, content: data, mode: mode, typeflag: tar.TypeReg})
			totalSize += int64(len(data))
		case tar.TypeSymlink:
			if err := lane.SymlinkContainmentError(rel, hdr.Linkname, "output tree"); err != nil {
				return nil, 0, err
			}
			entries = append(entries, canonicalEntry{name: name, linkname: hdr.Linkname, mode: 0o777, typeflag: tar.TypeSymlink})
		default:
			return nil, 0, fmt.Errorf("unsupported archive entry type %d at %q", hdr.Typeflag, rel)
		}
	}
	return entries, totalSize, nil
}

// writeCanonicalTar writes the collected entries as a tar archive with
// zeroed ownership and mtime for determinism.
func writeCanonicalTar(entries []canonicalEntry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: e.typeflag}
		// Uid, Gid, ModTime intentionally zero for determinism.
		switch e.typeflag {
		case tar.TypeDir:
			hdr.Name += "/"
		case tar.TypeReg:
			hdr.Size = int64(len(e.content))
		case tar.TypeSymlink:
			hdr.Linkname = e.linkname
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write(e.content); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FirstRegularFile scans a tar stream and returns a reader positioned at the
// first regular-file entry, together with its size. The returned reader is
// valid only until the next read from the underlying stream; callers must
// consume it before reading further. Used to pull a single produced file
// (an OCI-layout tar, or a provenance document) out of an engine container
// archive, which wraps even a single file in a one-entry tar.
func FirstRegularFile(r io.Reader) (io.Reader, int64, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, 0, fmt.Errorf("archive contains no regular file")
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			return tr, hdr.Size, nil
		}
	}
}

// WrapImageArchiveAsImage pulls the single OCI-layout tar file out of an
// engine container-archive stream and loads it as an image (the image
// output type under the engine flow). It reuses the image-load core shared
// with WrapImageOutputAsImage.
func (c *Client) WrapImageArchiveAsImage(ctx context.Context, r io.Reader, tag string, extra ...map[string]string) (primitive.Digest, int64, error) {
	inner, size, err := FirstRegularFile(r)
	if err != nil {
		return "", 0, fmt.Errorf("image output: %w", err)
	}
	return c.wrapImageFromReader(ctx, inner, size, tag, extra...)
}

// relUnderPrefix returns the portion of a tar entry name below prefix, and
// whether the entry is under prefix at all. prefix == "" or "." means the
// whole stream is under the root. The returned path has no leading or
// trailing slash; the subtree root itself returns ("", true).
func relUnderPrefix(name, prefix string) (string, bool) {
	clean := path.Clean(name)
	prefix = path.Clean(prefix)
	if prefix == "." || prefix == "" {
		if clean == "." {
			return "", true
		}
		return clean, true
	}
	if clean == prefix {
		return "", true
	}
	if rest, ok := strings.CutPrefix(clean, prefix+"/"); ok {
		return rest, true
	}
	return "", false
}
