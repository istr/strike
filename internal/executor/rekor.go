package executor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const rekorTimeout = 30 * time.Second

// RekorClient submits hashedrekord entries to a Rekor transparency log.
type RekorClient struct {
	URL       string
	PublicKey *ecdsa.PublicKey
	HTTP      *http.Client
}

// RekorEntry holds the transparency log response for a hashedrekord submission.
type RekorEntry struct {
	SignedEntryTimestamp []byte
	InclusionProof      *InclusionProof
	UUID                string
	Body                string // base64-encoded canonicalized entry (kept for SET verification)
	LogID               string
	LogIndex            int64
	IntegratedTime      int64
}

// InclusionProof holds the Merkle tree inclusion proof from the transparency log.
type InclusionProof struct {
	Hashes   []string
	RootHash string
	TreeSize int64
	LogIndex int64
}

// RekorTransientError represents a non-fatal Rekor submission failure.
// Transient errors (network, timeout, server errors) are wrapped in this type.
// SET verification failures are NOT wrapped -- they are hard errors.
type RekorTransientError struct {
	Err error
}

func (e *RekorTransientError) Error() string {
	return fmt.Sprintf("rekor transient: %v", e.Err)
}

func (e *RekorTransientError) Unwrap() error {
	return e.Err
}

// Annotations returns the Rekor metadata as a string map suitable for
// OCI manifest annotations.
func (e *RekorEntry) Annotations() map[string]string {
	m := map[string]string{
		"rekor.logIndex":             strconv.FormatInt(e.LogIndex, 10),
		"rekor.logID":                e.LogID,
		"rekor.integratedTime":       strconv.FormatInt(e.IntegratedTime, 10),
		"rekor.signedEntryTimestamp": base64.StdEncoding.EncodeToString(e.SignedEntryTimestamp),
	}
	if e.InclusionProof != nil {
		m["rekor.inclusionProof.rootHash"] = e.InclusionProof.RootHash
		m["rekor.inclusionProof.treeSize"] = strconv.FormatInt(e.InclusionProof.TreeSize, 10)
		m["rekor.inclusionProof.logIndex"] = strconv.FormatInt(e.InclusionProof.LogIndex, 10)
		m["rekor.inclusionProof.hashes"] = strings.Join(e.InclusionProof.Hashes, ",")
	}
	return m
}

// SubmitHashedRekord submits a hashedrekord entry to the Rekor transparency log.
// hexDigest is the hex-encoded SHA-256 digest (without "sha256:" prefix).
// sig is the raw signature bytes.
// pubKeyPEM is the PEM-encoded public key of the signer.
//
// Returns RekorTransientError for transient failures (network, timeout, 5xx).
// Returns a hard error for SET verification failures.
func (c *RekorClient) SubmitHashedRekord(ctx context.Context, hexDigest string, sig, pubKeyPEM []byte) (*RekorEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, rekorTimeout)
	defer cancel()

	reqBody := buildHashedRekordRequest(hexDigest, sig, pubKeyPEM)
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, &RekorTransientError{Err: fmt.Errorf("marshal request: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.URL+"/api/v1/log/entries", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, &RekorTransientError{Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &RekorTransientError{Err: fmt.Errorf("submit: %w", err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on HTTP response

	if resp.StatusCode != http.StatusCreated {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if readErr != nil {
			return nil, &RekorTransientError{Err: fmt.Errorf("status %d (body unreadable)", resp.StatusCode)}
		}
		return nil, &RekorTransientError{Err: fmt.Errorf("status %d: %s", resp.StatusCode, respBody)}
	}

	entry, err := parseRekorResponse(resp.Body)
	if err != nil {
		return nil, &RekorTransientError{Err: fmt.Errorf("parse response: %w", err)}
	}

	// Verify the signed entry timestamp (SET). A failed verification is a
	// hard error -- a forged response is a security event, not a transient
	// failure.
	if err := verifySET(entry, c.PublicKey); err != nil {
		return nil, fmt.Errorf("rekor SET verification failed: %w", err)
	}

	return entry, nil
}

// ParseRekorPublicKey parses an ECDSA public key from PEM bytes.
func ParseRekorPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, not ECDSA", pub)
	}
	return ecPub, nil
}

// buildHashedRekordRequest constructs the Rekor v1 API request body.
func buildHashedRekordRequest(hexDigest string, sig, pubKeyPEM []byte) map[string]any {
	return map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"signature": map[string]any{
				"content": base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(pubKeyPEM),
				},
			},
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     hexDigest,
				},
			},
		},
	}
}

// parseRekorResponse parses the Rekor v1 log entry creation response.
func parseRekorResponse(body io.Reader) (*RekorEntry, error) {
	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, err
	}

	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	for uuid, entryJSON := range entries {
		return parseSingleEntry(uuid, entryJSON)
	}

	return nil, fmt.Errorf("empty response")
}

// parseSingleEntry decodes one entry from the Rekor response map.
func parseSingleEntry(uuid string, entryJSON json.RawMessage) (*RekorEntry, error) {
	var raw struct { //nolint:govet // fieldalignment: field order matches JSON response structure
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
		Verification   struct {
			InclusionProof *struct { //nolint:govet // fieldalignment: field order matches JSON response
				Hashes   []string `json:"hashes"`
				LogIndex int64    `json:"logIndex"`
				RootHash string   `json:"rootHash"`
				TreeSize int64    `json:"treeSize"`
			} `json:"inclusionProof"`
			SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(entryJSON, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal entry: %w", err)
	}

	set, err := base64.StdEncoding.DecodeString(raw.Verification.SignedEntryTimestamp)
	if err != nil {
		return nil, fmt.Errorf("decode SET: %w", err)
	}

	entry := &RekorEntry{
		UUID:                uuid,
		LogIndex:            raw.LogIndex,
		LogID:               raw.LogID,
		IntegratedTime:      raw.IntegratedTime,
		SignedEntryTimestamp: set,
		Body:                raw.Body,
	}

	if raw.Verification.InclusionProof != nil {
		entry.InclusionProof = &InclusionProof{
			RootHash: raw.Verification.InclusionProof.RootHash,
			TreeSize: raw.Verification.InclusionProof.TreeSize,
			LogIndex: raw.Verification.InclusionProof.LogIndex,
			Hashes:   raw.Verification.InclusionProof.Hashes,
		}
	}

	return entry, nil
}

// verifySET verifies the signed entry timestamp against the Rekor public key.
// The SET is an ECDSA signature over the SHA-256 hash of the canonicalized
// log entry payload (body, integratedTime, logID, logIndex).
func verifySET(entry *RekorEntry, pub *ecdsa.PublicKey) error {
	payload, err := json.Marshal(setPayload{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogID:          entry.LogID,
		LogIndex:       entry.LogIndex,
	})
	if err != nil {
		return fmt.Errorf("canonicalize SET payload: %w", err)
	}

	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], entry.SignedEntryTimestamp) {
		return fmt.Errorf("ECDSA signature mismatch")
	}
	return nil
}

// setPayload is the canonical form of the log entry payload that the Rekor
// server signs. Field order must match JSON alphabetical sort for canonical
// encoding -- do not reorder.
type setPayload struct { //nolint:govet // fieldalignment: field order determines canonical JSON output for SET verification
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
}

// derivePublicKeyPEM loads a signing key and returns the PEM-encoded public key.
func derivePublicKeyPEM(keyPEM, password []byte) ([]byte, error) {
	privKey, err := loadCosignKey(keyPEM, password)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}
