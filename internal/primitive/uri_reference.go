package primitive

import (
	"errors"
	"net/url"
	"strings"
	"unicode"
)

// String returns the value as a plain string. It is the single sanctioned
// URIReference-to-string conversion: call sites use u.String(), never
// string(u).
func (u URIReference) String() string {
	return string(u)
}

// Validate checks the RFC 3986 URI-reference grammar the CUE scalar documents
// but does not encode: the value is non-empty, carries no whitespace or
// control character, and parses as a URI reference. Absolute and relative
// references are both accepted.
func (u URIReference) Validate() error {
	v := string(u)
	if v == "" {
		return errors.New("must not be empty")
	}
	if strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return errors.New("contains whitespace or a control character")
	}
	if _, err := url.Parse(v); err != nil {
		return errors.New("is not a URI reference")
	}
	return nil
}
