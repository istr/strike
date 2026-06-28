package deploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
)

// TestKeylessVerifySpike (R3) measures the Rekor v2 verification-direction
// mechanics against the live harness. It produces one real bundle, then
// answers three questions whose answers instruction 5a needs. It is a
// measurement: it dumps the concrete shapes via t.Log and asserts the
// current hypotheses. A failed assertion is a successful measurement that
// falsified a hypothesis -- read the printed actual value, do not adjust the
// test.
//
// Bring-up is identical to TestKeylessLive (see that test's comment).
func TestKeylessVerifySpike(t *testing.T) {
	if os.Getenv("SIGSTORE_ID_TOKEN") == "" {
		t.Skip("SIGSTORE_ID_TOKEN not set; see TestKeylessLive for harness bring-up")
	}
	harness, err := filepath.Abs(filepath.Join("..", "..", "test", "sigstore-local"))
	if err != nil {
		t.Fatalf("resolve harness dir: %v", err)
	}
	caddyRoot := filepath.Join(harness, "pki", "caddy-root.crt")
	rekorPub := filepath.Join(harness, "pki", "rekor-ed25519-pub.pem")
	for _, f := range []string{caddyRoot, rekorPub} {
		if _, statErr := os.Stat(f); statErr != nil {
			t.Fatalf("harness material missing: %v", statErr)
		}
	}

	trust := endpoint.CABundle{Type: "caBundle", Path: caddyRoot}
	eps := lane.KeylessEndpoints{
		Fulcio: endpoint.HTTPS{Address: endpoint.MustParseURL("https://fulcio.127.0.0.1.sslip.io:5555"), Trust: trust},
		Rekor:  endpoint.HTTPS{Address: endpoint.MustParseURL("https://rekor.127.0.0.1.sslip.io:3003"), Trust: trust},
		TSA:    endpoint.HTTPS{Address: endpoint.MustParseURL("https://tsa.127.0.0.1.sslip.io:3004"), Trust: trust},
	}
	token, err := ambientIDToken()
	if err != nil {
		t.Fatalf("ambientIDToken: %v", err)
	}

	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"spike.bin","digest":{"sha256":"` +
		strings.Repeat("0", 63) + `1"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)

	bundles, err := produceKeylessBundles(context.Background(), eps, token, [][]byte{stmt})
	if err != nil {
		t.Fatalf("produceKeylessBundles: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(bundles))
	}

	var pb protobundle.Bundle
	if uerr := protojson.Unmarshal(bundles[0], &pb); uerr != nil {
		t.Fatalf("protojson unmarshal bundle: %v", uerr)
	}
	vm := pb.GetVerificationMaterial()
	if vm == nil || len(vm.GetTlogEntries()) != 1 {
		t.Fatalf("expected exactly one tlog entry, got %v", vm)
	}
	tle := vm.GetTlogEntries()[0]

	// ---- Question 1: hashedrekord_v002 canonicalized body ----------------
	body := tle.GetCanonicalizedBody()
	if len(body) == 0 {
		t.Fatal("Q1: CanonicalizedBody is empty")
	}
	t.Logf("Q1 KindVersion: kind=%q version=%q",
		tle.GetKindVersion().GetKind(), tle.GetKindVersion().GetVersion())
	t.Logf("Q1 CanonicalizedBody (%d bytes) hex:\n%s", len(body), hex.EncodeToString(body))
	t.Logf("Q1 CanonicalizedBody as string:\n%s", string(body))
	// Hypothesis: the body is protojson of a rekor-tiles entry that carries
	// the leaf certificate and the signature. We do not assert its internal
	// schema here -- we DUMP it so 5a can pin the exact fields that must be
	// cross-checked against the DSSE envelope. Record the dump in the report.

	// ---- Question 2: RFC 6962 inclusion proof ----------------------------
	ip := tle.GetInclusionProof()
	if ip == nil {
		t.Fatal("Q2: InclusionProof is nil (producer bundle must carry one)")
	}
	leafHash := rfc6962LeafHash(body)
	t.Logf("Q2 leaf=%s index=%d treeSize=%d nHashes=%d root=%s",
		hex.EncodeToString(leafHash), ip.GetLogIndex(), ip.GetTreeSize(),
		len(ip.GetHashes()), hex.EncodeToString(ip.GetRootHash()))
	gotRoot, err := rfc6962RootFromProof(leafHash, ip.GetLogIndex(), ip.GetTreeSize(), ip.GetHashes())
	if err != nil {
		t.Fatalf("Q2: recompute root: %v", err)
	}
	if !bytes.Equal(gotRoot, ip.GetRootHash()) {
		t.Fatalf("Q2 FALSIFIED: recomputed root %s != carried root %s "+
			"(hand-rolled RFC6962 audit path is wrong; record both for 5a)",
			hex.EncodeToString(gotRoot), hex.EncodeToString(ip.GetRootHash()))
	}
	t.Log("Q2 CONFIRMED: hand-rolled RFC6962 root matches carried root")

	// ---- Question 3: C2SP checkpoint note + canonical log ID -------------
	cp := ip.GetCheckpoint()
	if cp == nil || cp.GetEnvelope() == "" {
		t.Fatal("Q3: checkpoint envelope is empty")
	}
	t.Logf("Q3 checkpoint envelope:\n%s", cp.GetEnvelope())

	pubPEM, err := os.ReadFile(filepath.Clean(rekorPub))
	if err != nil {
		t.Fatalf("Q3: read rekor pub: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatal("Q3: no PEM block in rekor pub")
	}
	edPub, err := parseEd25519PKIX(block.Bytes)
	if err != nil {
		t.Fatalf("Q3: parse rekor pub: %v", err)
	}

	// Hand-rolled canonical log ID per the rekor-tiles note rule.
	handLogID := sha256.Sum256(append([]byte(liveRekorOrigin+"\n\x01"), edPub...))
	// Oracle: the rekor-tiles note package's own derivation.
	_, oracleLogID, err := rekornote.KeyHash(liveRekorOrigin, edPub)
	if err != nil {
		t.Fatalf("Q3: rekornote.KeyHash: %v", err)
	}
	t.Logf("Q3 logID hand=%s oracle=%s",
		hex.EncodeToString(handLogID[:]), hex.EncodeToString(oracleLogID))
	if !bytes.Equal(handLogID[:], oracleLogID) {
		t.Fatalf("Q3 FALSIFIED: hand-rolled log ID != rekor-tiles note oracle")
	}
	if hex.EncodeToString(handLogID[:4]) != "1e050d3e" {
		t.Fatalf("Q3 FALSIFIED: log ID prefix = %s, expected 1e050d3e "+
			"(record the actual prefix for 5a)", hex.EncodeToString(handLogID[:4]))
	}
	t.Log("Q3 CONFIRMED: canonical C2SP log ID (prefix 1e050d3e), matches note oracle")

	// Verify the checkpoint note signature: the note is body + signature
	// lines; the 4-byte key ID after the "\u2014 <origin> " marker selects
	// the signature over the note body (text up to and including the blank
	// line separating body from signatures).
	if err := verifyCheckpointNote(cp.GetEnvelope(), liveRekorOrigin, edPub); err != nil {
		t.Fatalf("Q3 FALSIFIED: checkpoint note signature: %v", err)
	}
	t.Log("Q3 CONFIRMED: checkpoint note Ed25519 signature verifies")

	t.Log("R3 complete: paste the full -v output back for 5a authoring")
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
		return nil, errSpike("bad index/size: index=" + strconv.FormatInt(index, 10) +
			" size=" + strconv.FormatInt(size, 10))
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
		return nil, errSpike("audit path too short for tree size")
	}
	return hash, nil
}

type spikeError string

func (e spikeError) Error() string { return string(e) }
func errSpike(s string) error      { return spikeError("R3: " + s) }

// parseEd25519PKIX extracts an Ed25519 public key from PKIX/SPKI DER.
func parseEd25519PKIX(der []byte) (ed25519.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errSpike("rekor pub is not Ed25519")
	}
	return ed, nil
}

// verifyCheckpointNote checks the Ed25519 signature line of a C2SP signed
// note against pub. The note text is the body (everything up to and
// including the blank line); each signature line is
// "\u2014 <name> <base64(4-byte keyID || sig)>". The signature is over the
// note body bytes.
func verifyCheckpointNote(envelope, origin string, pub ed25519.PublicKey) error {
	const sep = "\n\n"
	idx := strings.Index(envelope, sep)
	if idx < 0 {
		return errSpike("note has no body/signature separator")
	}
	body := envelope[:idx+1] // body includes its trailing newline, not the blank line
	if !strings.HasPrefix(body, origin+"\n") {
		return errSpike("checkpoint origin does not match the expected log origin")
	}
	sigBlock := envelope[idx+len(sep):]
	for _, line := range strings.Split(strings.TrimRight(sigBlock, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "\u2014" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil || len(raw) <= 4 {
			continue
		}
		if ed25519.Verify(pub, []byte(body), raw[4:]) {
			return nil
		}
	}
	return errSpike("no signature line verified against the rekor pub")
}
