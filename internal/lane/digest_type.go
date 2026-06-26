package lane

import (
	"fmt"
	"strings"

	"github.com/istr/strike/internal/primitive"
)

// Digest invariants -- mirrored exactly by the CUE wire form (#Digest:
// =~"^sha256:<64-hex>$" in base-scalars.cue) and the internal #DigestRef
// (api-digest.cue). A change here without a matching schema change breaks
// cross-implementation verification.
const (
	digestAlgoSHA256   = "sha256"
	digestHexLenSHA256 = 64
)

// ParseDigest parses a wire digest of the form "sha256:<64 lowercase hex>" into
// the structured internal DigestRef. The empty string returns the zero
// DigestRef{} without error, so optional digest fields round-trip absence.
func ParseDigest(d primitive.Digest) (DigestRef, error) {
	s := string(d)
	if s == "" {
		return DigestRef{}, nil
	}
	i := strings.IndexByte(s, ':')
	if i < 1 {
		return DigestRef{}, fmt.Errorf("invalid digest %q: expected algorithm:hex", s)
	}
	algo := s[:i]
	hex := s[i+1:]
	if algo != digestAlgoSHA256 {
		return DigestRef{}, fmt.Errorf("invalid digest %q: algorithm must be %q",
			s, digestAlgoSHA256)
	}
	if len(hex) != digestHexLenSHA256 {
		return DigestRef{}, fmt.Errorf("invalid digest %q: hex must be %d chars, got %d",
			s, digestHexLenSHA256, len(hex))
	}
	for j := range len(hex) {
		c := hex[j]
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return DigestRef{}, fmt.Errorf("invalid digest %q: hex must be lowercase [0-9a-f], bad byte at offset %d",
				s, j)
		}
	}
	return DigestRef{Algorithm: algo, Hex: primitive.Sha256(hex)}, nil
}

// MustParseDigest parses a wire digest, panicking on invalid input. Use only for
// known-good values and test fixtures.
func MustParseDigest(d primitive.Digest) DigestRef {
	r, err := ParseDigest(d)
	if err != nil {
		panic(err)
	}
	return r
}

// Wire returns the canonical "algorithm:hex" wire Digest for d. The zero
// DigestRef returns the empty Digest, so optional digest fields round-trip
// absence.
func (d DigestRef) Wire() primitive.Digest {
	if d.Algorithm == "" {
		return ""
	}
	return primitive.Digest(d.Algorithm + ":" + string(d.Hex))
}

// String returns the canonical "algorithm:hex" representation of d.
func (d DigestRef) String() string {
	return string(d.Wire())
}

// IsZero reports whether d is the zero value (no algorithm or hex).
func (d DigestRef) IsZero() bool {
	return d.Algorithm == "" && d.Hex == ""
}
