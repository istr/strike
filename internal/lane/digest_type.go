package lane

import (
	"fmt"
	"strings"
)

// Digest is a content-addressed hash with explicit algorithm and hex fields.
// The structured representation makes it possible to validate digest values
// and to ban or require specific hash functions.
//
// JSON wire format remains "algorithm:hex" (e.g. "sha256:abcdef...") for
// compatibility with the CUE schema (#Digest: =~"^sha256:[a-f0-9]{64}$").
type Digest struct {
	Algorithm string // hash function name, e.g. "sha256"
	Hex       string // hex-encoded hash value
}

// ParseDigest parses a digest string of the form "algorithm:hex".
func ParseDigest(s string) (Digest, error) {
	if s == "" {
		return Digest{}, nil
	}
	i := strings.IndexByte(s, ':')
	if i < 1 {
		return Digest{}, fmt.Errorf("invalid digest %q: expected algorithm:hex", s)
	}
	return Digest{Algorithm: s[:i], Hex: s[i+1:]}, nil
}

// MustParseDigest parses a digest string, panicking on invalid input.
// Use only for known-good values and test fixtures.
func MustParseDigest(s string) Digest {
	d, err := ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

// String returns the canonical "algorithm:hex" representation.
func (d Digest) String() string {
	if d.Algorithm == "" {
		return ""
	}
	return d.Algorithm + ":" + d.Hex
}

// IsZero reports whether the digest is the zero value (no algorithm or hex).
func (d Digest) IsZero() bool {
	return d.Algorithm == "" && d.Hex == ""
}

// MarshalText implements encoding.TextMarshaler for transparent JSON
// serialization as a plain string ("sha256:hex").
func (d Digest) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for transparent JSON
// deserialization from a plain string ("sha256:hex").
func (d *Digest) UnmarshalText(text []byte) error {
	parsed, err := ParseDigest(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
