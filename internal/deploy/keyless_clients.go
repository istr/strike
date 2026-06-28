package deploy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"

	"github.com/digitorus/timestamp"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekortilespb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/transport"
)

// keylessHTTPTimeout bounds each keyless endpoint round trip. Rekor v2
// publishes checkpoints in batches; its client guidance recommends a
// generous write timeout.
const keylessHTTPTimeout = 30 * clock.Second

// keylessResponseLimit caps how much of an endpoint response is read.
const keylessResponseLimit = 1 << 20

// httpClientFor returns an HTTP client whose TLS configuration enforces the
// endpoint's declared trust anchor. The #KeylessEndpoints schema admits only
// https:// URLs, so every keyless connection is TLS with declared trust;
// there is no plaintext branch.
func httpClientFor(ep endpoint.HTTPS) (*http.Client, error) {
	cfg, err := transport.BuildTLSConfig(ep.Trust)
	if err != nil {
		return nil, fmt.Errorf("keyless: %w", err)
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   keylessHTTPTimeout,
	}, nil
}

// closeKeylessBody closes an endpoint response body, logging (not
// propagating) close errors, mirroring the executor Rekor client.
func closeKeylessBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		log.Printf("WARN close response body: %v", err)
	}
}

// postKeyless performs one POST against a keyless endpoint and returns the
// response body. Any status not in wantStatus is an error carrying the
// (truncated) response body.
func postKeyless(ctx context.Context, ep endpoint.HTTPS, path, contentType string, body []byte, header http.Header, wantStatus ...int) ([]byte, error) {
	client, err := httpClientFor(ep)
	if err != nil {
		return nil, err
	}
	base := ep.Address.URL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("keyless: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyless: %s%s: %w", base, path, err)
	}
	defer closeKeylessBody(resp)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, keylessResponseLimit))
	if err != nil {
		return nil, fmt.Errorf("keyless: read response: %w", err)
	}
	if !slices.Contains(wantStatus, resp.StatusCode) {
		return nil, fmt.Errorf("keyless: %s%s: status %d: %s", base, path, resp.StatusCode, respBody)
	}
	return respBody, nil
}

// fulcioCertificate obtains a short-lived signing certificate from Fulcio
// for the ephemeral public key, authenticated by the OIDC identity token.
// The proof of possession is an ASN.1 DER ECDSA signature over the SHA-256
// digest of the token subject (Fulcio API v2; mirrors sigstore-go's
// certificate request). Returns the DER-encoded leaf certificate.
func fulcioCertificate(ctx context.Context, ep endpoint.HTTPS, idToken string, key *ecdsa.PrivateKey) ([]byte, error) {
	subject, err := subjectFromIDToken(idToken)
	if err != nil {
		return nil, err
	}
	subjectDigest := sha256.Sum256([]byte(subject))
	pop, err := ecdsa.SignASN1(rand.Reader, key, subjectDigest[:])
	if err != nil {
		return nil, fmt.Errorf("keyless: sign proof of possession: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keyless: marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	reqBody, err := json.Marshal(map[string]any{
		"publicKeyRequest": map[string]any{
			"publicKey": map[string]any{
				"algorithm": "ECDSA",
				"content":   string(pubPEM),
			},
			"proofOfPossession": base64.StdEncoding.EncodeToString(pop),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("keyless: marshal fulcio request: %w", err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+idToken)
	respBody, err := postKeyless(ctx, ep, "/api/v2/signingCert", "application/json", reqBody, header, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Embedded struct {
			Chain struct {
				Certificates []string `json:"certificates"`
			} `json:"chain"`
		} `json:"signedCertificateEmbeddedSct"`
		Detached struct {
			Chain struct {
				Certificates []string `json:"certificates"`
			} `json:"chain"`
		} `json:"signedCertificateDetachedSct"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("keyless: parse fulcio response: %w", err)
	}
	certs := parsed.Embedded.Chain.Certificates
	if len(certs) == 0 {
		certs = parsed.Detached.Chain.Certificates
	}
	if len(certs) == 0 {
		return nil, errors.New("keyless: fulcio response contains no certificates")
	}
	block, _ := pem.Decode([]byte(certs[0]))
	if block == nil {
		return nil, errors.New("keyless: fulcio leaf certificate is not PEM")
	}
	return block.Bytes, nil
}

// tsaTimestamp obtains an RFC3161 timestamp over the DSSE signature. The
// returned bytes are the full timestamp response DER, which is what the
// sigstore bundle carries in Rfc3161Timestamps (mirrors sigstore-go's
// signer). The response is parsed once to fail fast on a malformed token.
func tsaTimestamp(ctx context.Context, ep endpoint.HTTPS, signature []byte) ([]byte, error) {
	sigDigest := sha256.Sum256(signature)
	req := &timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: sigDigest[:],
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("keyless: marshal timestamp request: %w", err)
	}
	respBody, err := postKeyless(ctx, ep, "/api/v1/timestamp", "application/timestamp-query", reqBytes, nil, http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	if _, err := timestamp.ParseResponse(respBody); err != nil {
		return nil, fmt.Errorf("keyless: invalid timestamp response: %w", err)
	}
	return respBody, nil
}

// rekorSubmitKeyless submits the DSSE signature to Rekor v2 as a
// hashedrekord over the signed digest (Rekor v2 records DSSE uploads this
// way) and returns the transparency log entry, which carries the inclusion
// proof and signed checkpoint. Hand-rolled HTTP POST per ratified R2: only
// the generated proto types are imported, so rekor-tiles' pkg/client (and
// its docker/otel dependency cluster) stays out of the compile graph.
func rekorSubmitKeyless(ctx context.Context, ep endpoint.HTTPS, paeDigest, sig, leafCertDER []byte) (*protorekor.TransparencyLogEntry, error) {
	req := &rekortilespb.CreateEntryRequest{
		Spec: &rekortilespb.CreateEntryRequest_HashedRekordRequestV002{
			HashedRekordRequestV002: &rekortilespb.HashedRekordRequestV002{
				Digest: paeDigest,
				Signature: &rekortilespb.Signature{
					Content: sig,
					Verifier: &rekortilespb.Verifier{
						Verifier: &rekortilespb.Verifier_X509Certificate{
							X509Certificate: &protocommon.X509Certificate{RawBytes: leafCertDER},
						},
						KeyDetails: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
		},
	}
	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("keyless: marshal rekor request: %w", err)
	}
	respBody, err := postKeyless(ctx, ep, "/api/v2/log/entries", "application/json", body, nil, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var tle protorekor.TransparencyLogEntry
	if err := protojson.Unmarshal(respBody, &tle); err != nil {
		return nil, fmt.Errorf("keyless: parse rekor response: %w", err)
	}
	return &tle, nil
}
