package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/token"
	"io/fs"
	"path"
)

// derBlobPrefix identifies a base64-encoded DER blob without decoding it. A
// DER certificate is a SEQUENCE, and a SEQUENCE longer than 255 bytes carries
// the two-byte length form 30 82, which base64 renders as "MII". No X.509
// certificate is short enough to fall below that: a P-256 SubjectPublicKeyInfo
// alone is 91 bytes and the signature another 70. Shorter DER objects --
// ECDSA signatures, SCT lists -- render as "MEQ" or "MIG" and are deliberately
// out of scope, because they are not the class this gate governs.
var derBlobPrefix = []byte("MII")

// derBlobSkipExts are the extensions this gate does not scan. A standalone
// certificate or key file is git's business rather than this gate's: the root
// .gitignore refuses all four, and test/sigstore-local/.gitignore refuses the
// harness material a local run mints into pki/, whose digests change on every
// rebuild and so can never be listed. This gate covers the other channel, a
// blob embedded in source, a fixture, or documentation.
var derBlobSkipExts = map[string]bool{".pem": true, ".key": true, ".crt": true, ".der": true}

const (
	// derBlobMinLen is the length below which a prefix match is coincidence
	// rather than a blob.
	derBlobMinLen = 40

	// anchorDocPath is the human-readable record of the fixture entries below.
	anchorDocPath = "docs/FIXTURE-TRUST-ANCHOR.md"

	// binarySniffLen is how far into a file the binary check looks for a NUL.
	binarySniffLen = 512

	unlistedBlobMessage  = "base64 DER blob is not in the lintdoc allowlist"
	strayRecordMessage   = "blob in the fixture record is not a fixture artifact"
	missingRecordMessage = "fixture artifact missing from the record"
)

// derBlob is one blob the tree is permitted to carry: the SHA-256 of its
// base64 text as it appears in the tree, a label naming what it is, and
// whether docs/FIXTURE-TRUST-ANCHOR.md is required to record it. The digest is
// taken over the base64 text rather than over the decoded bytes, so the gate
// needs no base64 and no DER decoding.
type derBlob struct {
	digest   string
	label    string
	recorded bool
}

// derBlobs is the allowlist, and it is the truth. Every base64-encoded DER
// blob anywhere in this tree is one of these; anything else is a finding.
// docs/FIXTURE-TRUST-ANCHOR.md repeats the recorded half so a reader can
// compare the two, but this list is what the gate reads.
//
// Potential optimization: the golden entries exist only because the local
// sigstore harness mints fresh material on every rebuild, so regenerating the
// goldens replaces them and this list has to be updated in the same commit. If
// the golden chain is ever rebased onto RFC 9500 material the way the fixture
// anchors are, those eight entries disappear and the list stops moving.
var derBlobs = []derBlob{
	// Fixture material over the RFC 9500 testECCP256 key (ADR-056 D8),
	// recorded verbatim in docs/FIXTURE-TRUST-ANCHOR.md.
	{
		digest:   "348de86f9feea9730bf327ee217f5ab446d32b0e03a4e76002acfe01c24d7ff7",
		label:    "fixture anchor, self-signed CA:TRUE",
		recorded: true,
	},
	{
		digest:   "a1d40b436f21833ab50c11ba93477faaa14ab45a92738c2938f6a6c9d0a7bfbc",
		label:    "fixture intermediate, issued by the anchor",
		recorded: true,
	},
	{
		digest:   "2f68153791d0e00b68be6bed15ba297e2646f3c39d87a8d2118d02b756b40021",
		label:    "fixture leaf, self-signed CA:FALSE",
		recorded: true,
	},
	{
		digest:   "e4fd0b7055fe05b4ff419208a40b619b0364942d6608301c08e9399b3f8a7b5d",
		label:    "fixture anchor truncated, valid base64 that is not a certificate",
		recorded: true,
	},
	{
		digest:   "18b6bad88863ade7fa20054f26a850eba939487bc70a238fe824e08125a98163",
		label:    "fixture anchor with a base64url tail, not base64",
		recorded: true,
	},

	// Sigstore material in internal/verify/testdata/golden, produced by
	// tools/gengolden against the local harness. See the note above.
	{
		digest: "75a026df761577de87a2e0c7aaaf5ba4d6a1ebd7e5ea3b3998274f995dffc039",
		label:  "golden trusted root: harness Fulcio CA",
	},
	{
		digest: "d4fa89755c0638c3f019de4607d7ab7d60c10fa5a6eed9cf784b3ca354c4f7e0",
		label:  "golden trusted root: harness TSA root",
	},
	{
		digest: "70cd2025389aa389a07506758924e6e42daae8a9d3b2aaaf672f7e9da122bd8f",
		label:  "golden trusted root: harness TSA intermediate",
	},
	{
		digest: "974221dda08d81dc00eeefc2ef7be73e9da632289e58646a7abb54e333cee2bd",
		label:  "golden trusted root: harness TSA timestamping leaf",
	},
	{
		digest: "07c139fd695f339ffabafddbde6a636c4851d1f50a4397fb171b974e0d6551d7",
		label:  "golden bundles: Fulcio leaf for tester@strike.localhost",
	},
	{
		digest: "4a1c97cb31f35a1742926b87a67e434892a4f00647ee5940dff4ceb398e7c800",
		label:  "golden sealed bundle: RFC3161 timestamp token",
	},
	{
		digest: "bfb7bace9fb62149b93a5d32c288f86505a36d6db77dede2d1f161b99e8515de",
		label:  "golden engine-context bundle: RFC3161 timestamp token",
	},
	{
		digest: "c0b85c754ae383dd87bfd750619c684961e70744a73480bb92058abbc9eba6d9",
		label:  "golden informational bundle: RFC3161 timestamp token",
	},

	// Sigstore material in internal/deploy/testdata/base-sbom. Checked in from
	// a harness run and read by the base-SBOM verification tests; no generator
	// in this tree produces it, so these do not move.
	{
		digest: "f06699c63092e457ad450e7195a077cee844b0b943252d6541703d1e29975e6c",
		label:  "base-SBOM trusted root: harness Fulcio CA",
	},
	{
		digest: "1f59731731af2d3ef460178143d02db5f96c4967e06c8214a24a1eb43add15a4",
		label:  "base-SBOM trusted root: harness TSA root",
	},
	{
		digest: "a4d92b278da040443aa9cf80a8a2237a2ed340b3e20d1da21e3ef8a90c058cd0",
		label:  "base-SBOM trusted root: harness TSA intermediate",
	},
	{
		digest: "e2834f8f06b80aaf6d3dc47946e30744d5051a751ca58416ebfc771c7ae9b0b0",
		label:  "base-SBOM trusted root: harness TSA timestamping leaf",
	},
	{
		digest: "0671c3c9ffa68d428a86c3f044b8fac82abdf8a5a5a818c812ace7ec0e9a1deb",
		label:  "base-SBOM cyclonedx bundle: Fulcio leaf",
	},
	{
		digest: "9b6acca137288902b3a2f49800c39e9b77ecf94c7d205f358e75eb33db04755e",
		label:  "base-SBOM spdx bundle: Fulcio leaf",
	},
	{
		digest: "8cf0e4d92e161f429646017adee65e0dfe1d16b22e6408e74d7f50696fa55e36",
		label:  "base-SBOM cyclonedx bundle: RFC3161 timestamp token",
	},
	{
		digest: "38094600d5feb0ff771f8d0b06284992e5a873a482d05a4e0d4f6b26d8d1d30c",
		label:  "base-SBOM spdx bundle: RFC3161 timestamp token",
	},

	// Trust-root replicas inline in the lane parser fixtures. Checked in from
	// a harness run; parser input only.
	{
		digest: "5d6a81e9db926c13d1b908ac2355c470fa403324c04e09bca96e56c191e5b6cf",
		label:  "lane trustroot fixtures: sigstore Fulcio root",
	},
	{
		digest: "c9636cd2aa143f2edf958a52f94123730b960262786f858b86f2d5d6916866d6",
		label:  "lane trustroot fixtures: harness TSA timestamping leaf",
	},
}

// blobHit is one candidate token and the byte offset it starts at.
type blobHit struct {
	token []byte
	off   int
}

// isBlobByte reports whether b can appear inside a base64 or base64url token.
// The base64url alphabet is included so a value that is deliberately not
// standard base64 is still seen as one token rather than as a prefix of one.
func isBlobByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '+', b == '/', b == '=', b == '-', b == '_':
		return true
	default:
		return false
	}
}

// derBlobTokens returns every maximal run of blob bytes in content that starts
// with the DER prefix and is long enough not to be a coincidence.
func derBlobTokens(content []byte) []blobHit {
	var hits []blobHit
	start := -1
	for i := 0; i <= len(content); i++ {
		if i < len(content) && isBlobByte(content[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start < 0 {
			continue
		}
		if tok := content[start:i]; len(tok) >= derBlobMinLen && bytes.HasPrefix(tok, derBlobPrefix) {
			hits = append(hits, blobHit{off: start, token: tok})
		}
		start = -1
	}
	return hits
}

// blobDigest is the allowlist key: SHA-256 over the token's own bytes.
func blobDigest(token []byte) string {
	sum := sha256.Sum256(token)
	return hex.EncodeToString(sum[:])
}

// lookupBlob returns the allowlist entry for a digest.
func lookupBlob(digest string) (derBlob, bool) {
	for _, b := range derBlobs {
		if b.digest == digest {
			return b, true
		}
	}
	return derBlob{}, false
}

// isBinary reports whether content is build output rather than text. Ignored
// build artifacts sit in a developer's working tree -- the built strike binary
// above all -- and reading them is both waste and a source of coincidental
// prefix matches.
func isBinary(content []byte) bool {
	return bytes.IndexByte(content[:min(len(content), binarySniffLen)], 0) >= 0
}

// checkDERBlobs records every base64-encoded DER blob in a scanned file that
// the allowlist does not name.
func (g *gate) checkDERBlobs() error {
	return g.walkTree(func(name string, d fs.DirEntry) error {
		if derBlobSkipExts[path.Ext(d.Name())] {
			return nil
		}
		return g.scanDERBlobs(name)
	})
}

// scanDERBlobs reports the unlisted blobs in one file, positioned at the byte
// each starts on. The file is registered only when there is something to say
// about it.
func (g *gate) scanDERBlobs(name string) error {
	content, err := fs.ReadFile(g.root.FS(), name)
	if err != nil {
		return err
	}
	if isBinary(content) {
		return nil
	}
	var file *token.File
	for _, h := range derBlobTokens(content) {
		digest := blobDigest(h.token)
		if _, ok := lookupBlob(digest); ok {
			continue
		}
		if file == nil {
			file = g.file(name, content)
		}
		g.report(file, h.off, fmt.Sprintf("%s (sha256 %s)", unlistedBlobMessage, digest))
	}
	return nil
}

// checkAnchorRecord keeps the record and the allowlist from drifting apart.
// The tree-wide check already rejects an unlisted blob wherever it sits; this
// one adds the other direction, that every recorded entry is in the record and
// nothing else is.
func (g *gate) checkAnchorRecord() error {
	content, err := fs.ReadFile(g.root.FS(), anchorDocPath)
	if err != nil {
		return err
	}
	file := g.file(anchorDocPath, content)
	seen := make(map[string]bool, len(derBlobs))
	for _, h := range derBlobTokens(content) {
		digest := blobDigest(h.token)
		if b, ok := lookupBlob(digest); !ok || !b.recorded {
			g.report(file, h.off, fmt.Sprintf("%s (sha256 %s)", strayRecordMessage, digest))
			continue
		}
		seen[digest] = true
	}
	for _, b := range derBlobs {
		if b.recorded && !seen[b.digest] {
			g.report(file, 0, fmt.Sprintf("%s: %s (sha256 %s)", missingRecordMessage, b.label, b.digest))
		}
	}
	return nil
}
