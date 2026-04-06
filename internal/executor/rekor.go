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
	"time"

	"github.com/istr/strike/internal/lane"
)

const rekorTimeout = 30 * time.Second

// RekorClient submits hashedrekord entries to a Rekor transparency log.
type RekorClient struct {
	PublicKey *ecdsa.PublicKey
	HTTP      *http.Client
	URL       string
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

// SubmitHashedRekord submits a hashedrekord entry to the Rekor transparency log.
// hexDigest is the hex-encoded SHA-256 digest (without "sha256:" prefix).
// sig is the raw signature bytes.
// pubKeyPEM is the PEM-encoded public key of the signer.
//
// Returns a verified lane.RekorEntry on success.
// Returns RekorTransientError for transient failures (network, timeout, 5xx).
// Returns a hard error for SET verification failures.
func (c *RekorClient) SubmitHashedRekord(ctx context.Context, hexDigest string, sig, pubKeyPEM []byte) (*lane.RekorEntry, error) {
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

	parsed, err := parseRekorResponse(resp.Body)
	if err != nil {
		return nil, &RekorTransientError{Err: fmt.Errorf("parse response: %w", err)}
	}

	// Verify the signed entry timestamp (SET). A failed verification is a
	// hard error -- a forged response is a security event, not a transient
	// failure.
	if setErr := verifySET(parsed, c.PublicKey); setErr != nil {
		return nil, fmt.Errorf("rekor SET verification failed: %w", setErr)
	}

	// Build the lane.RekorEntry from parsed response.
	entry := &lane.RekorEntry{
		UUID:                 parsed.uuid,
		LogIndex:             parsed.logIndex,
		LogID:                parsed.logID,
		IntegratedTime:       parsed.integratedTime,
		Body:                 parsed.body,
		SignedEntryTimestamp: base64.StdEncoding.EncodeToString(parsed.signedEntryTimestamp),
	}
	if parsed.inclusionProof != nil {
		entry.InclusionProof = lane.InclusionProof{
			RootHash: parsed.inclusionProof.rootHash,
			TreeSize: parsed.inclusionProof.treeSize,
			LogIndex: parsed.inclusionProof.logIndex,
			Hashes:   parsed.inclusionProof.hashes,
		}
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

// parsedRekorEntry holds the raw Rekor API response fields needed for
// SET verification and conversion to the output format.
type parsedRekorEntry struct {
	inclusionProof       *parsedInclusionProof
	body                 string
	logID                string
	uuid                 string
	signedEntryTimestamp []byte
	logIndex             int64
	integratedTime       int64
}

type parsedInclusionProof struct {
	rootHash string
	hashes   []string
	logIndex int64
	treeSize int64
}

// parseRekorResponse parses the Rekor v1 log entry creation response.
func parseRekorResponse(body io.Reader) (*parsedRekorEntry, error) {
	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, err
	}

	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	for uuid, entryJSON := range entries {
		entry, err := parseSingleEntry(entryJSON)
		if err != nil {
			return nil, err
		}
		entry.uuid = uuid
		return entry, nil
	}

	return nil, fmt.Errorf("empty response")
}

// parseSingleEntry decodes one entry from the Rekor response map.
func parseSingleEntry(entryJSON json.RawMessage) (*parsedRekorEntry, error) {
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

	entry := &parsedRekorEntry{
		logIndex:             raw.LogIndex,
		logID:                raw.LogID,
		integratedTime:       raw.IntegratedTime,
		signedEntryTimestamp: set,
		body:                 raw.Body,
	}

	if raw.Verification.InclusionProof != nil {
		entry.inclusionProof = &parsedInclusionProof{
			rootHash: raw.Verification.InclusionProof.RootHash,
			treeSize: raw.Verification.InclusionProof.TreeSize,
			logIndex: raw.Verification.InclusionProof.LogIndex,
			hashes:   raw.Verification.InclusionProof.Hashes,
		}
	}

	return entry, nil
}

// verifySET verifies the signed entry timestamp against the Rekor public key.
// The SET is an ECDSA signature over the SHA-256 hash of the canonicalized
// log entry payload (body, integratedTime, logID, logIndex).
func verifySET(entry *parsedRekorEntry, pub *ecdsa.PublicKey) error {
	payload, err := json.Marshal(setPayload{
		Body:           entry.body,
		IntegratedTime: entry.integratedTime,
		LogID:          entry.logID,
		LogIndex:       entry.logIndex,
	})
	if err != nil {
		return fmt.Errorf("canonicalize SET payload: %w", err)
	}

	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], entry.signedEntryTimestamp) {
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
