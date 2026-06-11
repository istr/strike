package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekortilespb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/deploy"
)

// Inclusion verifies the Rekor v2 transparency-log inclusion of the bundle's
// statement, fail-closed on every binding:
//   - the logged hashedrekord_v002 entry commits to the same payload digest,
//     signature, and leaf certificate as the DSSE bundle;
//   - the RFC6962 inclusion proof recomputes the carried root;
//   - the Ed25519-signed C2SP checkpoint commits to that root and tree size,
//     under the log key the trusted root names, with the note origin bound to
//     that key by the canonical signed-note key ID.
func Inclusion(pb *ParsedBundle, tm *TrustedMaterial, leaf *x509.Certificate) error {
	tle := pb.TLE
	body := tle.GetCanonicalizedBody()
	if len(body) == 0 {
		return fmt.Errorf("%w: empty canonicalized body", ErrInclusion)
	}

	// 1. The logged entry is the same artifact as the DSSE bundle.
	var entry rekortilespb.Entry
	if err := protojson.Unmarshal(body, &entry); err != nil {
		return fmt.Errorf("%w: canonicalized body: %w", ErrInclusion, err)
	}
	hr := entry.GetSpec().GetHashedRekordV002()
	if hr == nil {
		return fmt.Errorf("%w: not a hashedrekord_v002 entry", ErrInclusion)
	}
	pae := deploy.PAEEncode(pb.Envelope.GetPayloadType(), pb.Envelope.GetPayload())
	paeDigest := sha256.Sum256(pae)
	if hr.GetData().GetAlgorithm() != commonpb.HashAlgorithm_SHA2_256 ||
		!bytes.Equal(hr.GetData().GetDigest(), paeDigest[:]) {
		return fmt.Errorf("%w: logged digest does not match the signed payload", ErrInclusion)
	}
	if !bytes.Equal(hr.GetSignature().GetContent(), pb.Envelope.GetSignatures()[0].GetSig()) {
		return fmt.Errorf("%w: logged signature does not match the bundle", ErrInclusion)
	}
	if !bytes.Equal(hr.GetSignature().GetVerifier().GetX509Certificate().GetRawBytes(), pb.LeafDER) {
		return fmt.Errorf("%w: logged certificate does not match the bundle leaf", ErrInclusion)
	}

	// 2. The proof recomputes the carried root.
	ip := tle.GetInclusionProof()
	if ip == nil {
		return fmt.Errorf("%w: no inclusion proof", ErrInclusion)
	}
	root, err := rfc6962RootFromProof(rfc6962LeafHash(body), ip.GetLogIndex(), ip.GetTreeSize(), ip.GetHashes())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInclusion, err)
	}
	if !bytes.Equal(root, ip.GetRootHash()) {
		return fmt.Errorf("%w: recomputed root does not match the proof root", ErrInclusion)
	}

	// 3. The checkpoint signs that root, under the trusted log key.
	if err := verifyCheckpoint(ip.GetCheckpoint().GetEnvelope(), tle.GetLogId().GetKeyId(),
		ip.GetTreeSize(), ip.GetRootHash(), tm); err != nil {
		return fmt.Errorf("%w: %w", ErrInclusion, err)
	}

	// 4. integratedTime is unsigned under Rekor v2 and normally absent; if a
	// positive value is asserted, it must fall within the leaf validity.
	if it := tle.GetIntegratedTime(); it > 0 {
		t := clock.Unix(it, 0)
		if t.Before(leaf.NotBefore) || t.After(leaf.NotAfter) {
			return fmt.Errorf("%w: integrated time outside leaf validity", ErrInclusion)
		}
	}
	return nil
}

// verifyCheckpoint verifies a C2SP signed-note checkpoint with the canonical
// note implementation, then confirms it commits to the expected tree size and
// root. The trusted log key is selected by the entry's log ID; the note origin
// is bound to that key by the canonical signed-note key ID before the note is
// opened, so a spoofed origin cannot select a different verifier.
func verifyCheckpoint(envelope string, logID []byte, treeSize int64, rootHash []byte, tm *TrustedMaterial) error {
	pub, ok := tm.rekorKeys[hex.EncodeToString(logID)]
	if !ok {
		return fmt.Errorf("no trusted log key for log ID %s", hex.EncodeToString(logID))
	}
	origin, _, found := strings.Cut(envelope, "\n")
	if !found {
		return fmt.Errorf("checkpoint has no origin line")
	}
	// Bind origin to the trusted key: the canonical signed-note key ID is
	// sha256(origin + "\n" + 0x01 + pub) and must equal the trusted log ID.
	canonical := sha256.Sum256(append([]byte(origin+"\n\x01"), pub...))
	if !bytes.Equal(canonical[:], logID) {
		return fmt.Errorf("checkpoint origin does not match the trusted log key")
	}
	// Verify the signature with the canonical signed-note implementation.
	vkey, err := note.NewEd25519VerifierKey(origin, pub)
	if err != nil {
		return fmt.Errorf("note verifier key: %w", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return fmt.Errorf("note verifier: %w", err)
	}
	n, err := note.Open([]byte(envelope), note.VerifierList(verifier))
	if err != nil {
		return fmt.Errorf("checkpoint signature: %w", err)
	}
	// Confirm the verified note commits to the proof's tree size and root.
	// Checkpoint body lines: origin, tree size (decimal), base64(root hash).
	lines := strings.Split(strings.TrimRight(n.Text, "\n"), "\n")
	if len(lines) < 3 {
		return fmt.Errorf("checkpoint body too short")
	}
	gotSize, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return fmt.Errorf("checkpoint tree size: %w", err)
	}
	gotRoot, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return fmt.Errorf("checkpoint root hash: %w", err)
	}
	if gotSize != treeSize {
		return fmt.Errorf("checkpoint tree size %d != proof %d", gotSize, treeSize)
	}
	if !bytes.Equal(gotRoot, rootHash) {
		return fmt.Errorf("checkpoint root does not match the proof root")
	}
	return nil
}

// rfc6962LeafHash returns SHA-256(0x00 || body), the RFC 6962 leaf hash.
func rfc6962LeafHash(body []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(body)
	return h.Sum(nil)
}

// rfc6962NodeHash returns SHA-256(0x01 || left || right).
func rfc6962NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// rfc6962RootFromProof recomputes the tree root from a leaf hash, its index,
// the tree size, and the audit path (leaf to root), per RFC 6962 2.1.1.
func rfc6962RootFromProof(leaf []byte, index, size int64, path [][]byte) ([]byte, error) {
	if index < 0 || size < 0 || index >= size {
		return nil, fmt.Errorf("bad index/size: index=%d size=%d", index, size)
	}
	hash := leaf
	fn, sn := index, size-1
	for _, sibling := range path {
		if fn == sn || fn%2 == 1 {
			hash = rfc6962NodeHash(sibling, hash)
			for fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			hash = rfc6962NodeHash(hash, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, fmt.Errorf("audit path too short for tree size")
	}
	return hash, nil
}
