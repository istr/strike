package primitive

import (
	"fmt"
	"strings"
)

// ParseDigest validates that d is a canonical wire digest -- "sha256:" followed
// by 64 lowercase hex characters -- and returns it unchanged. The algorithm is
// fixed to sha256 (docs/ADR-008-cryptographic-primitives.md): there is no
// per-call algorithm choice, so a non-sha256 prefix or a wrong hex length is an
// error. The empty Digest returns the empty Digest without error, so optional
// digest fields round-trip absence. Use at the boundary where a digest enters
// from outside the schema-validated lane (engine inspect, image-ref
// extraction); inside the pipeline a Digest is already constrained by #Digest.
func ParseDigest(d Digest) (Digest, error) {
	s := string(d)
	if s == "" {
		return "", nil
	}
	body, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return "", fmt.Errorf("invalid digest %q: must start with \"sha256:\"", s)
	}
	if len(body) != 64 {
		return "", fmt.Errorf("invalid digest %q: hex must be 64 chars, got %d",
			s, len(body))
	}
	for i := range len(body) {
		c := body[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf(
				"invalid digest %q: hex must be lowercase [0-9a-f], bad byte at offset %d",
				s, i)
		}
	}
	return d, nil
}

// DigestFromHex builds a canonical wire Digest from a bare lowercase sha256 hex
// body by prepending the fixed "sha256:" algorithm prefix (ADR-008). The body is
// supplied by the caller -- typically hex.EncodeToString over a freshly computed
// sha256 sum -- so the result is well-formed by construction and is not
// re-validated; use ParseDigest for a digest crossing in from outside the
// schema-validated lane. It is the inverse of Hex.
func DigestFromHex(body string) Digest {
	return Digest("sha256:" + body)
}

// Hex returns the bare lowercase hex body of d -- the encoded portion without
// the "sha256:" algorithm prefix. The zero Digest yields the empty Sha256.
func (d Digest) Hex() Sha256 {
	return Sha256(strings.TrimPrefix(string(d), "sha256:"))
}

// String returns the canonical "sha256:<hex>" wire form of d as a plain string.
// It is the single sanctioned Digest-to-string conversion: call sites use
// d.String(), never string(d), so no type conversion sits in an argument list.
func (d Digest) String() string {
	return string(d)
}
