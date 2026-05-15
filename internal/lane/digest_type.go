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

// Digest invariants -- mirrored exactly by the CUE schema
// (#Digest: =~"^sha256:[a-f0-9]{64}$"). A change here without a
// matching schema change breaks cross-implementation verification.
const (
	digestAlgoSHA256   = "sha256"
	digestHexLenSHA256 = 64
)

// ParseDigest parses a digest string of the form "sha256:<64 lowercase hex>".
// The empty string returns the zero Digest{} without error, so that
// optional digest fields can round-trip absence through JSON.
func ParseDigest(s string) (Digest, error) {
	if s == "" {
		return Digest{}, nil
	}
	i := strings.IndexByte(s, ':')
	if i < 1 {
		return Digest{}, fmt.Errorf("invalid digest %q: expected algorithm:hex", s)
	}
	algo := s[:i]
	hex := s[i+1:]
	if algo != digestAlgoSHA256 {
		return Digest{}, fmt.Errorf("invalid digest %q: algorithm must be %q",
			s, digestAlgoSHA256)
	}
	if len(hex) != digestHexLenSHA256 {
		return Digest{}, fmt.Errorf("invalid digest %q: hex must be %d chars, got %d",
			s, digestHexLenSHA256, len(hex))
	}
	for j := range len(hex) {
		c := hex[j]
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return Digest{}, fmt.Errorf("invalid digest %q: hex must be lowercase [0-9a-f], bad byte at offset %d",
				s, j)
		}
	}
	return Digest{Algorithm: algo, Hex: hex}, nil
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
