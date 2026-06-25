package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/istr/strike/internal/lane"
)

// captureSnap holds the fields needed by the canonical state digest
// encoding. Deliberately unexported; callers interact with StateDigest only.
type captureSnap struct {
	name   string
	image  string
	output []byte
}

// StateDigest computes a canonical SHA-256 digest over a set of state
// captures. The encoding is deterministic and order-independent:
// captures are sorted by name, and each field is length-prefixed with
// an 8-byte big-endian uint64 so no separator bytes are needed.
//
// The empty-input case is well-defined: SHA-256 of the empty byte
// sequence (e3b0c442...). The loop writes nothing and the hash of the
// empty buffer is returned.
func StateDigest(captures []captureSnap) lane.DigestRef {
	sorted := make([]captureSnap, len(captures))
	copy(sorted, captures)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].name < sorted[j].name
	})

	var buf bytes.Buffer
	var lenBuf [8]byte
	for _, c := range sorted {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(c.name)))
		buf.Write(lenBuf[:])
		buf.WriteString(c.name)

		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(c.image)))
		buf.Write(lenBuf[:])
		buf.WriteString(c.image)

		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(c.output)))
		buf.Write(lenBuf[:])
		buf.Write(c.output)
	}

	sum := sha256.Sum256(buf.Bytes())
	return lane.DigestRef{Algorithm: "sha256", Hex: lane.Sha256(hex.EncodeToString(sum[:]))}
}
