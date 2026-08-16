package registry

import (
	"archive/tar"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// CanonicalLayerFromTarForTest wraps the unexported canonicalLayerFromTar for
// same-package external tests (TestCanonicalLayer_*). It must stay here, not in
// regtest: it is a wrapper around the unit under test and reaches an unexported
// function, which regtest cannot (and canonicalLayerFromTar must not be
// exported).
func CanonicalLayerFromTarForTest(r io.Reader, stripPrefix, destPrefix string) (v1.Layer, int64, error) {
	return canonicalLayerFromTar(r, stripPrefix, destPrefix)
}

// WriteCanonicalTarNamesForTest wraps writeCanonicalTar for same-package
// external tests, building one directory entry per name. It exists to reach
// the locality check, which no exported entry point can be made to violate.
func WriteCanonicalTarNamesForTest(names []string) ([]byte, error) {
	entries := make([]canonicalEntry, 0, len(names))
	for _, n := range names {
		entries = append(entries, canonicalEntry{name: n, mode: 0o755, typeflag: tar.TypeDir})
	}
	return writeCanonicalTar(entries)
}
