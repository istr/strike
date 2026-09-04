package primitive

import (
	"fmt"
	"strings"
)

// NewImageRef returns the ImageRef form of s. It does not validate -- callers
// constructing a reference from already-trusted parts (a digest computed in
// process, a test input) use it to own the conversion in this package; a
// reference crossing in from outside the schema-validated lane is validated at
// parse.
func NewImageRef(s string) ImageRef {
	return ImageRef(s)
}

// Digest returns the content address r is pinned to: the portion after the
// last '@', validated as a canonical wire digest. The split takes the last
// '@' rather than the first because that is what the anchored #ImageRef
// pattern means. A reference carrying no '@' is not an error -- a local image
// that has never been pushed carries no content address -- and yields the
// empty Digest, which the caller distinguishes from a resolved one. A '@' with
// an empty or malformed body is an error: the reference declares a content
// address and the declaration is wrong.
func (r ImageRef) Digest() (Digest, error) {
	i := strings.LastIndexByte(string(r), '@')
	if i < 0 {
		return "", nil
	}
	body := Digest(string(r)[i+1:])
	if body == "" {
		return "", fmt.Errorf("invalid image reference %q: empty digest after \"@\"", string(r))
	}
	return ParseDigest(body)
}
