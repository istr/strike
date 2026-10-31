package primitive

import (
	"errors"
	"net/url"
	"strings"
)

// String returns the value as a plain string. It is the single sanctioned
// StringOrURI-to-string conversion: call sites use s.String(), never
// string(s).
func (s StringOrURI) String() string {
	return string(s)
}

// Validate checks the RFC 7519 StringOrURI grammar the CUE scalar documents
// but does not encode: the value is non-empty, and a value containing ':' is
// a URI with a scheme. A colon-free value (an email address) is accepted as
// it stands.
func (s StringOrURI) Validate() error {
	v := string(s)
	if v == "" {
		return errors.New("must not be empty")
	}
	if !strings.Contains(v, ":") {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return errors.New("contains ':' but is not a URI")
	}
	if u.Scheme == "" {
		return errors.New("contains ':' but carries no URI scheme")
	}
	return nil
}
