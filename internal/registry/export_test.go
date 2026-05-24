package registry

import (
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
