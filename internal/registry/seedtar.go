package registry

import (
	"archive/tar"
	"bytes"
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
// SaveImage; layerDiffID identifies which content layer to read by its
// uncompressed-content digest (diff_id). inImagePath is the already-resolved
// path within that layer to select ("" or "." selects the whole layer); the
// caller computes any output-type offset, so this function knows nothing of
// output types. destPrefix is where the selected content is rooted in the
// emitted tar (e.g. the input's path relative to the workdir); "" or "."
// roots at the tar root.
//
// The selected subtree is walked to enforce ADR-034 lexical symlink
// containment (lane.SymlinkContainmentError); links are enumerated, never
// followed. A single regular file and a directory tree are both supported. A
// missing inImagePath is reported as a not-found error, not deferred to an
// engine mount failure. The emitted tar is deterministic: name-sorted
// entries, zeroed mtime and ownership, preserved file modes, verbatim
// (contained) symlinks.
func SeedTarFromImage(tarBytes []byte, layerDiffID, inImagePath, destPrefix string) ([]byte, error) {
	layerBytes, err := OutputLayer(tarBytes, layerDiffID)
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

// PackTarFromImage selects a content subtree from a producer image and returns
// a canonical tar rooted at destPath, ready to become one layer of a packed
// image. It differs from SeedTarFromImage in two ways, both because a pack tar
// becomes part of an image rootfs rather than being seeded into an existing
// volume: every directory an entry name implies carries its own entry, and a
// single regular file selected at destPath takes fileMode from the pack
// declaration instead of the mode the producer wrote. A directory tree keeps
// the producer's modes throughout.
//
// destPath is the in-image destination without its leading slash. Containment
// is enforced by the same rules SeedTarFromImage relies on, plus the locality
// check in writeCanonicalTar.
func PackTarFromImage(tarBytes []byte, layerDiffID, inImagePath, destPath string, fileMode int64) ([]byte, error) {
	layerBytes, err := OutputLayer(tarBytes, layerDiffID)
	if err != nil {
		return nil, err
	}

	entries, matched, err := collectSeedEntries(bytes.NewReader(layerBytes), inImagePath, destPath)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("subpath %q not found in producer content", inImagePath)
	}

	for i := range entries {
		if entries[i].typeflag == tar.TypeReg && entries[i].name == destPath {
			entries[i].mode = fileMode
		}
	}
	entries = withImpliedDirs(entries)

	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	return writeCanonicalTar(entries)
}

// withImpliedDirs returns entries plus a directory entry for every parent
// directory an entry name implies and that is not already present. Content
// seeded into a volume can rely on the volume root existing; a layer cannot,
// so the directories leading to a pack layer's content must be in the layer.
func withImpliedDirs(entries []canonicalEntry) []canonicalEntry {
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		present[e.name] = true
	}
	for _, e := range entries {
		for dir := path.Dir(e.name); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if present[dir] {
				continue
			}
			present[dir] = true
			entries = append(entries, canonicalEntry{
				name:     dir,
				mode:     0o755,
				typeflag: tar.TypeDir,
			})
		}
	}
	return entries
}

// ValidateImageMount inspects a producer image's selected subtree for the
// outside-workdir mount path (ADR-036), without emitting a tar. tarBytes is
// the OCI-layout archive from SaveImage; layerDiffID identifies the content
// layer by its uncompressed-content digest (diff_id); inImagePath is the
// caller-resolved path within that layer ("" or "." selects the whole layer).
//
// It walks the same producer layer the seed path walks, enforcing ADR-034
// containment, and returns the resolved kind of the subtree root:
//
//   - MountKindDirectory: mountable as a read-only image volume.
//   - MountKindFile: a single regular file, which the OCI runtime cannot
//     mount as a directory-granular overlay; the caller rejects this in
//     lane terms before constructing a mount.
//   - MountKindMissing: returned as a not-found error here, so the caller
//     surfaces strike's own diagnostic rather than an engine mount failure.
//
// The bytes are not copied; only headers and symlink targets are inspected.
func ValidateImageMount(tarBytes []byte, layerDiffID, inImagePath string) (MountKind, error) {
	layerBytes, err := OutputLayer(tarBytes, layerDiffID)
	if err != nil {
		return MountKindMissing, err
	}
	noop := func(_ *tar.Header, _ string, _ *tar.Reader) error { return nil }
	kind, err := walkProducerLayer(bytes.NewReader(layerBytes), inImagePath, noop)
	if err != nil {
		return MountKindMissing, err
	}
	if kind == MountKindMissing && path.Clean(inImagePath) != "." && inImagePath != "" {
		return MountKindMissing, fmt.Errorf("subpath %q not found in producer content", inImagePath)
	}
	return kind, nil
}

// OutputLayer returns the uncompressed content of the layer identified by
// layerDiffID, checked against that identity before it is returned. The image
// config maps the diff_id to a blob descriptor, but the config is the engine's
// own account of its store; the content hash is therefore recomputed here and
// compared against layerDiffID, which the control plane computed from the
// layer it assembled, before the engine ever saw it. An engine whose export
// is internally consistent but does not match the produced bytes is caught
// here, fail-closed. This makes the export handoff a checked courier on the
// consumer side exactly as it is on the sealing path (ADR-051 D4), and it
// needs no anchor beyond the one the output handle already carries.
// Consumers: the pack-input and seed paths in this package, and the deploy
// region catalog (ADR-051 D9).
func OutputLayer(tarBytes []byte, layerDiffID string) ([]byte, error) {
	img, err := ImageFromOCITar(tarBytes)
	if err != nil {
		return nil, err
	}

	want, err := v1.NewHash(layerDiffID)
	if err != nil {
		return nil, fmt.Errorf("parse layer diff id %q: %w", layerDiffID, err)
	}

	layer, err := img.LayerByDiffID(want)
	if err != nil {
		return nil, fmt.Errorf("output layer %q not found in step image: %w", layerDiffID, err)
	}

	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("uncompress layer %q: %w", layerDiffID, err)
	}
	content, readErr := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		return nil, fmt.Errorf("close layer %q: %w", layerDiffID, closeErr)
	}
	if readErr != nil {
		return nil, fmt.Errorf("read layer %q: %w", layerDiffID, readErr)
	}

	got, _, err := v1.SHA256(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("hash layer %q: %w", layerDiffID, err)
	}
	if got != want {
		return nil, fmt.Errorf("exported layer content hashes to %s, the produced output declares %s", got, want)
	}
	return content, nil
}

// readOCITarBlobs reads an OCI-layout tar and returns its blob contents keyed
// by clean path, plus the raw index.json bytes.
func readOCITarBlobs(tarBytes []byte) (map[string][]byte, []byte, error) {
	blobs := make(map[string][]byte)
	var indexBytes []byte

	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read OCI tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, readErr := io.ReadAll(tr)
		if readErr != nil {
			return nil, nil, fmt.Errorf("read %q: %w", hdr.Name, readErr)
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
		return nil, nil, fmt.Errorf("index.json not found in OCI tar")
	}
	return blobs, indexBytes, nil
}

// MountKind is the resolved shape of a selected producer subtree. The zero
// value is MountKindMissing, so an unset MountKind is fail-closed: no match
// means no mount, never accidentally readable as "directory, therefore
// mountable".
type MountKind int

// MountKind values for the three resolved subtree shapes.
const (
	MountKindMissing   MountKind = iota // subpath matched nothing
	MountKindFile                       // subtree root is a single regular file
	MountKindDirectory                  // subtree root is a directory tree
)

// rootKind returns the kind for a subtree root entry. A directory root
// promotes missing to directory but does not demote an already-resolved
// kind; a regular-file root is the single-file selection.
func rootKind(typeflag byte, current MountKind) MountKind {
	switch typeflag {
	case tar.TypeDir:
		if current == MountKindMissing {
			return MountKindDirectory
		}
		return current
	case tar.TypeReg:
		return MountKindFile
	default:
		return current
	}
}

// walkProducerLayer walks a single producer content layer, selecting the
// subtree under inImagePath. It enforces ADR-034 symlink containment with
// the lane-surface "input tree" frame, regardless of delivery path. For
// each selected, non-root entry it invokes emit; a seed pass collects the
// entry, a validate pass ignores it. It returns the resolved kind of the
// subtree root: a lone matched regular file is MountKindFile, any matched
// directory content is MountKindDirectory, no match is MountKindMissing.
//
// The kind detection mirrors seedEntryRel: a directory subtree root is the
// skipped entry whose rel is "" with TypeDir; a single-file selection is
// the matched entry whose rel is "" with TypeReg.
func walkProducerLayer(r io.Reader, inImagePath string, emit func(hdr *tar.Header, rel string, tr *tar.Reader) error) (MountKind, error) {
	kind := MountKindMissing
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return MountKindMissing, fmt.Errorf("read layer: %w", err)
		}

		kind, err = walkEntry(hdr, inImagePath, kind, emit, tr)
		if err != nil {
			return MountKindMissing, err
		}
	}
	return kind, nil
}

// walkEntry processes one tar entry for walkProducerLayer. It returns the
// updated kind and any error. Factored out to keep the loop body under the
// cognitive-complexity threshold.
func walkEntry(hdr *tar.Header, inImagePath string, kind MountKind, emit func(*tar.Header, string, *tar.Reader) error, tr *tar.Reader) (MountKind, error) {
	rel, ok := relUnderPrefix(hdr.Name, inImagePath)
	if !ok {
		return kind, nil
	}

	if hdr.Typeflag == tar.TypeSymlink {
		if cErr := lane.SymlinkContainmentError(rel, hdr.Linkname, "input tree"); cErr != nil {
			return MountKindMissing, cErr
		}
	}

	isRoot := rel == "" || rel == "."
	if isRoot {
		kind = rootKind(hdr.Typeflag, kind)
		if hdr.Typeflag == tar.TypeDir {
			return kind, nil // skip directory root entry
		}
	} else {
		kind = MountKindDirectory
	}

	if emitErr := emit(hdr, rel, tr); emitErr != nil {
		return MountKindMissing, emitErr
	}
	return kind, nil
}

// collectSeedEntries walks a producer layer and collects the selected
// entries, re-rooted under destPrefix, for the canonical seed tar. It is a
// thin wrapper over walkProducerLayer that performs the entry collection;
// matched reports whether the subpath resolved to anything.
func collectSeedEntries(r io.Reader, inImagePath, destPrefix string) ([]canonicalEntry, bool, error) {
	var entries []canonicalEntry
	emit := func(hdr *tar.Header, rel string, tr *tar.Reader) error {
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
				return fmt.Errorf("read %q: %w", rel, readErr)
			}
			entries = append(entries, canonicalEntry{name: name, content: data, mode: mode, typeflag: tar.TypeReg})
		case tar.TypeSymlink:
			entries = append(entries, canonicalEntry{name: name, linkname: hdr.Linkname, mode: 0o777, typeflag: tar.TypeSymlink})
		default:
			return fmt.Errorf("unsupported archive entry type %d at %q", hdr.Typeflag, rel)
		}
		return nil
	}
	kind, err := walkProducerLayer(r, inImagePath, emit)
	if err != nil {
		return nil, false, err
	}
	return entries, kind != MountKindMissing, nil
}
