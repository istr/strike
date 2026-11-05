package testutil

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustrootpb "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/istr/strike/internal/wire"
)

// Trust-root coordinates of the local sigstore harness. They mirror its Caddy
// CT route and the checkpoint origin its Rekor signs; they are configuration of
// that harness, not a rule the producer and verifier must agree on. sigstore-go
// matches the checkpoint origin against the hostname of the Rekor base URL, so
// that URL carries the origin even though the producer dials the sslip.io
// endpoint. Nothing dials the CT base URL: the SCT is embedded in the Fulcio
// leaf and checked offline against the log key.
const (
	harnessRekorOrigin   = "rekor.localhost"
	harnessRekorBaseURL  = "https://" + harnessRekorOrigin
	harnessCTBaseURL     = "https://ct.127.0.0.1.sslip.io:6962/strike-ct"
	trustedRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
)

// HarnessTrustedRoot assembles the sigstore trusted_root.json of the running
// harness under harnessDir: the Fulcio chain fetched with GET
// /api/v2/trustBundle from fulcioURL over client, and the Rekor log public key,
// the TSA certificate chain and the CT log public key exported under pki/. The
// caller supplies the client, because it decides how the harness is dialed.
// The timestamp authority mints a fresh chain on every start, so the document
// holds only for the harness start whose chain pki/ currently carries.
func HarnessTrustedRoot(ctx context.Context, client *http.Client, fulcioURL, harnessDir string) ([]byte, error) {
	pki := filepath.Join(harnessDir, "pki")
	fulcioCerts, err := fulcioChain(ctx, client, fulcioURL)
	if err != nil {
		return nil, err
	}
	rekorBlock, err := readPEM(filepath.Join(pki, "rekor-ed25519-pub.pem"), "rekor public key")
	if err != nil {
		return nil, err
	}
	edPub, err := wire.ParseEd25519PKIX(rekorBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rekor public key: %w", err)
	}
	tsaCerts, err := certChain(filepath.Join(pki, "tsa-certchain.pem"), "tsa")
	if err != nil {
		return nil, err
	}
	if len(tsaCerts) < 2 {
		return nil, fmt.Errorf("tsa chain has %d certificates, want >= 2", len(tsaCerts))
	}
	ctfeBlock, err := readPEM(filepath.Join(pki, "ctfe-pub.pem"), "ctfe public key")
	if err != nil {
		return nil, err
	}
	// RFC6962 CT log id is sha256(DER SubjectPublicKeyInfo), i.e. the PEM body
	// of an openssl `ec -pubout` PUBLIC KEY block. This differs from the Rekor
	// v2 C2SP signed-note key id computed by wire.NoteKeyID.
	ctLogID := sha256.Sum256(ctfeBlock.Bytes)

	out, err := protojson.Marshal(trustedRootProto(trustMaterials{
		fulcioURI:   fulcioURL,
		fulcioCerts: fulcioCerts,
		tsaCerts:    tsaCerts,
		rekorKeyDER: rekorBlock.Bytes,
		rekorLogID:  wire.NoteKeyID(harnessRekorOrigin, edPub),
		ctfeKeyDER:  ctfeBlock.Bytes,
		ctfeLogID:   ctLogID[:],
	}))
	if err != nil {
		return nil, fmt.Errorf("marshal trusted root: %w", err)
	}
	return out, nil
}

// trustMaterials are the harness inputs the trust root is assembled from,
// grouped so the proto construction stays one readable literal.
type trustMaterials struct {
	fulcioURI   string
	fulcioCerts []*x509.Certificate
	tsaCerts    []*x509.Certificate
	rekorKeyDER []byte
	rekorLogID  []byte
	ctfeKeyDER  []byte
	ctfeLogID   []byte
}

// trustedRootProto lays out the sigstore TrustedRoot. The last certificate of
// each chain is the trust anchor. Neither log key has a certificate validity of
// its own, and sigstore-go's trusted-root loader requires a start, so the Fulcio
// root NotBefore is used as a lower bound -- it precedes any entry this harness
// can have signed.
func trustedRootProto(m trustMaterials) *trustrootpb.TrustedRoot {
	fulcioRoot := m.fulcioCerts[len(m.fulcioCerts)-1]
	tsaRoot := m.tsaCerts[len(m.tsaCerts)-1]
	return &trustrootpb.TrustedRoot{
		MediaType: trustedRootMediaType,
		CertificateAuthorities: []*trustrootpb.CertificateAuthority{{
			Uri:       m.fulcioURI,
			CertChain: &protocommon.X509CertificateChain{Certificates: rawCertificates(m.fulcioCerts)},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(fulcioRoot.NotBefore),
				End:   timestamppb.New(fulcioRoot.NotAfter),
			},
		}},
		TimestampAuthorities: []*trustrootpb.CertificateAuthority{{
			CertChain: &protocommon.X509CertificateChain{Certificates: rawCertificates(m.tsaCerts)},
			ValidFor: &protocommon.TimeRange{
				Start: timestamppb.New(tsaRoot.NotBefore),
				End:   timestamppb.New(tsaRoot.NotAfter),
			},
		}},
		Tlogs: []*trustrootpb.TransparencyLogInstance{{
			BaseUrl:       harnessRekorBaseURL,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   m.rekorKeyDER,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ED25519,
				ValidFor:   &protocommon.TimeRange{Start: timestamppb.New(fulcioRoot.NotBefore)},
			},
			LogId: &protocommon.LogId{KeyId: m.rekorLogID},
		}},
		Ctlogs: []*trustrootpb.TransparencyLogInstance{{
			BaseUrl:       harnessCTBaseURL,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes:   m.ctfeKeyDER,
				KeyDetails: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				ValidFor:   &protocommon.TimeRange{Start: timestamppb.New(fulcioRoot.NotBefore)},
			},
			LogId: &protocommon.LogId{KeyId: m.ctfeLogID},
		}},
	}
}

// fulcioChain fetches and parses the Fulcio certificate chain via
// GET /api/v2/trustBundle. The returned order is the served order (leaf-most
// first, trust anchor last).
func fulcioChain(ctx context.Context, client *http.Client, fulcioURL string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fulcioURL+"/api/v2/trustBundle", nil)
	if err != nil {
		return nil, fmt.Errorf("trustBundle request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustBundle fetch: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	var tb struct {
		Chains []struct {
			Certificates []string `json:"certificates"`
		} `json:"chains"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&tb); decErr != nil {
		return nil, fmt.Errorf("trustBundle decode: %w", decErr)
	}
	if len(tb.Chains) == 0 || len(tb.Chains[0].Certificates) == 0 {
		return nil, errors.New("trustBundle has no certificates")
	}
	var chain []*x509.Certificate
	for _, p := range tb.Chains[0].Certificates {
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return nil, errors.New("trustBundle certificate is not PEM")
		}
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr != nil {
			return nil, fmt.Errorf("parse fulcio certificate: %w", certErr)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// readPEM reads a single-block PEM file, naming it in any error.
func readPEM(path, what string) (*pem.Block, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", what)
	}
	return block, nil
}

// certChain reads a concatenated PEM certificate chain in file order.
func certChain(path, what string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read %s chain: %w", what, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		cert, certErr := x509.ParseCertificate(b.Bytes)
		if certErr != nil {
			return nil, fmt.Errorf("parse %s certificate: %w", what, certErr)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// rawCertificates converts parsed certificates to the proto chain entries,
// preserving order.
func rawCertificates(certs []*x509.Certificate) []*protocommon.X509Certificate {
	out := make([]*protocommon.X509Certificate, len(certs))
	for i, c := range certs {
		out[i] = &protocommon.X509Certificate{RawBytes: c.Raw}
	}
	return out
}
