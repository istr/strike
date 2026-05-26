package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/istr/strike/internal/lane"
)

// SeedTarFromImage selects a content subtree from a producer image and
// returns a canonical tar ready to seed into a container volume (ADR-036
// inside-workdir input delivery). tarBytes is the OCI-layout archive from
// SaveImage; the image must have exactly one content layer. inImagePath is
// the already-resolved path within that layer to select ("" or "." selects
// the whole layer); the caller computes any output-type offset, so this
// function knows nothing of output types. destPrefix is where the selected
// content is rooted in the emitted tar (e.g. the input's path relative to
// the workdir); "" or "." roots at the tar root.
//
// The selected subtree is walked to enforce ADR-034 lexical symlink
// containment (lane.SymlinkContainmentError); links are enumerated, never
// followed. A single regular file and a directory tree are both supported. A
// missing inImagePath is reported as a not-found error, not deferred to an
// engine mount failure. The emitted tar is deterministic: name-sorted
// entries, zeroed mtime and ownership, preserved file modes, verbatim
// (contained) symlinks.
func SeedTarFromImage(tarBytes []byte, inImagePath, destPrefix string) ([]byte, error) {
	layerBytes, err := singleLayerFromOCITar(tarBytes)
	if err != nil {
		return nil, err
	}

	entries, matched, err := collectSeedEntries(bytes.NewReader(layerBytes), inImagePath, destPrefix)
	if err != nil {
		return nil, err
	}
	if !matched && path.Clean(inImagePath) != "." && inImagePath != "" {
		return nil, fmt.Errorf("subpath %q not found in producer content", inImagePath)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	return writeCanonicalTar(entries)
}

// singleLayerFromOCITar reads an OCI-layout tar archive in memory and
// returns the uncompressed content of the single layer. No temp dir is used.
func singleLayerFromOCITar(tarBytes []byte) ([]byte, error) {
	blobs := make(map[string][]byte)
	var indexBytes []byte

	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read OCI tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, readErr := io.ReadAll(tr)
		if readErr != nil {
			return nil, fmt.Errorf("read %q: %w", hdr.Name, readErr)
		}
		clean := path.Clean(hdr.Name)
		if clean == "index.json" {
			indexBytes = data
		}
		if strings.HasPrefix(clean, "blobs/") {
			blobs[clean] = data
		}
	}

	if indexBytes == nil {
		return nil, fmt.Errorf("index.json not found in OCI tar")
	}

	var idx v1.IndexManifest
	if err := json.Unmarshal(indexBytes, &idx); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	if len(idx.Manifests) != 1 {
		return nil, fmt.Errorf("expected single image in layout, found %d", len(idx.Manifests))
	}

	manifestPath := fmt.Sprintf("blobs/%s/%s", idx.Manifests[0].Digest.Algorithm, idx.Manifests[0].Digest.Hex)
	manifestBytes, ok := blobs[manifestPath]
	if !ok {
		return nil, fmt.Errorf("manifest blob %q not found", manifestPath)
	}

	var manifest v1.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(manifest.Layers) != 1 {
		return nil, fmt.Errorf("expected 1 content layer, got %d", len(manifest.Layers))
	}

	layerPath := fmt.Sprintf("blobs/%s/%s", manifest.Layers[0].Digest.Algorithm, manifest.Layers[0].Digest.Hex)
	layerBlob, ok := blobs[layerPath]
	if !ok {
		return nil, fmt.Errorf("layer blob %q not found", layerPath)
	}

	return decompressIfGzip(layerBlob)
}

// decompressIfGzip attempts gzip decompression; if the data is not gzipped,
// it returns the raw bytes (an uncompressed layer).
func decompressIfGzip(data []byte) ([]byte, error) {
	if !isGzip(data) {
		return data, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	out, readErr := io.ReadAll(gz)
	if closeErr := gz.Close(); closeErr != nil {
		return nil, fmt.Errorf("close gzip: %w", closeErr)
	}
	if readErr != nil {
		return nil, fmt.Errorf("decompress layer: %w", readErr)
	}
	return out, nil
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// collectSeedEntries walks a layer tar, selects entries under inImagePath,
// re-roots them under destPrefix, and validates symlink containment.
func collectSeedEntries(r io.Reader, inImagePath, destPrefix string) ([]canonicalEntry, bool, error) {
	var (
		entries []canonicalEntry
		matched bool
	)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("read layer: %w", err)
		}

		rel, ok := relUnderPrefix(hdr.Name, inImagePath)
		if !ok {
			continue
		}
		rel, skip := seedEntryRel(rel, inImagePath, hdr.Typeflag)
		matched = true
		if skip {
			continue
		}

		name := path.Join(destPrefix, rel)
		if name == "" || name == "." {
			name = path.Base(path.Clean(inImagePath))
		}
		mode := int64(hdr.FileInfo().Mode().Perm())

		switch hdr.Typeflag {
		case tar.TypeDir:
			entries = append(entries, canonicalEntry{name: name, mode: mode, typeflag: tar.TypeDir})
		case tar.TypeReg:
			data, readErr := io.ReadAll(tr)
			if readErr != nil {
				return nil, false, fmt.Errorf("read %q: %w", rel, readErr)
			}
			entries = append(entries, canonicalEntry{name: name, content: data, mode: mode, typeflag: tar.TypeReg})
		case tar.TypeSymlink:
			if err := lane.SymlinkContainmentError(rel, hdr.Linkname, "seed tree"); err != nil {
				return nil, false, err
			}
			entries = append(entries, canonicalEntry{name: name, linkname: hdr.Linkname, mode: 0o777, typeflag: tar.TypeSymlink})
		default:
			return nil, false, fmt.Errorf("unsupported archive entry type %d at %q", hdr.Typeflag, rel)
		}
	}
	return entries, matched, nil
}

// seedEntryRel resolves the relative path for a seed entry at the subtree
// root. For directories, the root itself is skipped (matching
// collectArchiveEntries). For a single-file match (inImagePath names a
// file exactly), rel is "" so path.Join(destPrefix, "") == destPrefix --
// the caller passes the full destination path. When destPrefix is also
// empty, collectSeedEntries falls back to the file's basename.
func seedEntryRel(rel, _ string, typeflag byte) (string, bool) {
	if rel != "" && rel != "." {
		return rel, false
	}
	if typeflag == tar.TypeDir {
		return "", true // skip directory root
	}
	return "", false
}
