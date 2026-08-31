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
	"net"
	"net/http"
	"slices"

	"github.com/digitorus/timestamp"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekortilespb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// keylessHTTPTimeout bounds each keyless endpoint round trip. Rekor v2
// publishes checkpoints in batches; its client guidance recommends a generous
// write timeout. The test harness declares a bound of its own for a different
// connection class; the two are independent and neither is derived from the
// other.
const keylessHTTPTimeout = 30 * clock.Second

// keylessResponseLimit caps how much of an endpoint response is read.
const keylessResponseLimit = 1 << 20

// HTTPClientFor returns an HTTP client that reaches ep through the
// resolved-and-verified dial: the declared host is resolved by the lane's DoT
// resolver, the connection goes to the address that resolver answered with,
// and the presented certificate is verified against the declared host. A dial
// to any authority other than the declared one is rejected, and a plaintext
// dial is rejected structurally rather than by convention.
//
// The observed server identity is deliberately not recorded. ADR-030 records a
// connection identity when and only when it participates in the trust chain,
// and these endpoints are anchored in their own content: the Fulcio leaf chains
// to a trusted-root certificate authority, the transparency-log entry carries
// an inclusion proof against the log key, and the RFC3161 token verifies
// against the timestamp-authority chain -- each offline, against an anchor
// evaluated at an authenticated reference time (ADR-053). No sealed claim would
// be corroborated by the channel, and the bundle these endpoints produce is the
// signature over the attestation itself, so an identity recorded there would
// describe the signing chain from inside what that chain signs.
func HTTPClientFor(ep endpoint.HTTPS, dialer *transport.Dialer) (*http.Client, error) {
	if dialer == nil {
		return nil, errors.New("keyless: resolver-backed dialer required")
	}
	if ep.Address.Host == "" {
		return nil, errors.New("keyless: endpoint host required")
	}
	dialAddr := ep.Address
	if dialAddr.Port == nil {
		port := primitive.Port(443)
		dialAddr.Port = &port
	}
	expected := string(dialAddr.Authority())
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				if addr != expected {
					return nil, fmt.Errorf("keyless: dial %q outside the declared endpoint %q rejected", addr, expected)
				}
				vc, dialErr := dialer.DialPeer(ctx, dialAddr.Host, *dialAddr.Port, ep.Trust)
				if dialErr != nil {
					return nil, dialErr
				}
				return vc.Conn(), nil
			},
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return nil, fmt.Errorf("keyless: plaintext dial to %q rejected; the endpoint is https-only", addr)
			},
		},
		Timeout: keylessHTTPTimeout,
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
func postKeyless(ctx context.Context, ep endpoint.HTTPS, dialer *transport.Dialer, path, contentType string, body []byte, header http.Header, wantStatus ...int) ([]byte, error) {
	client, err := HTTPClientFor(ep, dialer)
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
func fulcioCertificate(ctx context.Context, ep endpoint.HTTPS, dialer *transport.Dialer, idToken string, key *ecdsa.PrivateKey) ([]byte, error) {
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
	respBody, err := postKeyless(ctx, ep, dialer, "/api/v2/signingCert", "application/json", reqBody, header, http.StatusOK)
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
func tsaTimestamp(ctx context.Context, ep endpoint.HTTPS, dialer *transport.Dialer, signature []byte) ([]byte, error) {
	sigDigest := sha256.Sum256(signature)
	req := &timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: sigDigest[:],
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("keyless: marshal timestamp request: %w", err)
	}
	respBody, err := postKeyless(ctx, ep, dialer, "/api/v1/timestamp", "application/timestamp-query", reqBytes, nil, http.StatusOK, http.StatusCreated)
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
func rekorSubmitKeyless(ctx context.Context, ep endpoint.HTTPS, dialer *transport.Dialer, paeDigest, sig, leafCertDER []byte) (*protorekor.TransparencyLogEntry, error) {
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
	respBody, err := postKeyless(ctx, ep, dialer, "/api/v2/log/entries", "application/json", body, nil, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var tle protorekor.TransparencyLogEntry
	if err := protojson.Unmarshal(respBody, &tle); err != nil {
		return nil, fmt.Errorf("keyless: parse rekor response: %w", err)
	}
	return &tle, nil
}
