package executor_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

// --------------------------------------------------------------------------.
// Test helpers.
// --------------------------------------------------------------------------.

// generateRekorKey generates an ephemeral ECDSA P-256 key pair for a fake
// Rekor server. Returns the private key and its PEM-encoded public key.
func generateRekorKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return key, pubPEM
}

// generateSignerKey generates an ephemeral ECDSA P-256 key pair for artifact
// signing. Returns the raw signature over digest, the PEM-encoded public key,
// and the hex digest.
func generateSignerKey(t *testing.T) (sig, pubKeyPEM []byte, hexDigest string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a fake digest and sign it.
	digest := sha256.Sum256([]byte("test-artifact"))
	hexDigest = fmt.Sprintf("%x", digest[:])

	r, s, signErr := ecdsa.Sign(rand.Reader, key, digest[:])
	if signErr != nil {
		t.Fatal(signErr)
	}
	sig = make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return sig, pubKeyPEM, hexDigest
}

// signSET signs a Rekor SET payload with the given private key.
func signSET(t *testing.T, rekorKey *ecdsa.PrivateKey, body string, integratedTime int64, logID string, logIndex int64) []byte {
	t.Helper()
	payload := struct { //nolint:govet // fieldalignment: field order determines canonical JSON for SET verification
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{
		Body:           body,
		IntegratedTime: integratedTime,
		LogID:          logID,
		LogIndex:       logIndex,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	setBytes, err := ecdsa.SignASN1(rand.Reader, rekorKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return setBytes
}

// fakeRekorResponse builds a canned Rekor 201 response with a valid SET.
func fakeRekorResponse(t *testing.T, rekorKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	body := base64.StdEncoding.EncodeToString([]byte(`{"kind":"hashedrekord"}`))
	logID := strings.Repeat("ab", 32) // 64 hex chars to match CUE constraint
	var integratedTime int64 = 1700000000
	var logIndex int64 = 42

	set := signSET(t, rekorKey, body, integratedTime, logID, logIndex)

	entry := map[string]any{
		"body":           body,
		"integratedTime": integratedTime,
		"logID":          logID,
		"logIndex":       logIndex,
		"verification": map[string]any{
			"signedEntryTimestamp": base64.StdEncoding.EncodeToString(set),
			"inclusionProof": map[string]any{
				"rootHash": strings.Repeat("cc", 32),
				"treeSize": 100,
				"logIndex": logIndex,
				"hashes":   []string{strings.Repeat("11", 32), strings.Repeat("22", 32), strings.Repeat("33", 32)},
			},
		},
	}

	resp := map[string]any{strings.Repeat("ab", 32): entry}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// invalidSETHandler returns a handler that responds with a valid-looking Rekor
// entry but with an invalid signed entry timestamp.
func invalidSETHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body := base64.StdEncoding.EncodeToString([]byte(`{"kind":"hashedrekord"}`))
		entry := map[string]any{
			"body":           body,
			"integratedTime": 1700000000,
			"logID":          strings.Repeat("ab", 32),
			"logIndex":       42,
			"verification": map[string]any{
				"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("bad-sig")),
				"inclusionProof": map[string]any{
					"rootHash": strings.Repeat("cc", 32),
					"treeSize": 100,
					"logIndex": 42,
					"hashes":   []string{strings.Repeat("11", 32)},
				},
			},
		}
		resp := map[string]any{strings.Repeat("cd", 32): entry}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp) //nolint:errcheck,gosec // test helper
	}
}

// fakeRekorHandler returns an HTTP handler that validates the request structure
// and responds with a canned Rekor 201 response.
func fakeRekorHandler(t *testing.T, rekorKey *ecdsa.PrivateKey) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/log/entries" {
			t.Errorf("path = %s, want /api/v1/log/entries", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %s, want application/json", ct)
		}

		var body map[string]any
		if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
			t.Errorf("decode request body: %v", decErr)
		}
		if body["kind"] != "hashedrekord" {
			t.Errorf("kind = %v, want hashedrekord", body["kind"])
		}
		if body["apiVersion"] != "0.0.1" {
			t.Errorf("apiVersion = %v, want 0.0.1", body["apiVersion"])
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(fakeRekorResponse(t, rekorKey)) //nolint:errcheck,gosec // test helper
	}
}

// rekorOutputEntry and rekorOutputProof are no longer needed —
// SubmitHashedRekord now returns *lane.RekorEntry directly.

// --------------------------------------------------------------------------.
// Tests.
// --------------------------------------------------------------------------.

func TestSubmitHashedRekord(t *testing.T) {
	rekorKey, rekorPubPEM := generateRekorKey(t)
	rekorPub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	sig, pubKeyPEM, hexDigest := generateSignerKey(t)

	tests := []struct {
		handler     http.HandlerFunc
		name        string
		wantErr     bool
		wantWarning bool
		checkEntry  bool
	}{
		{
			name:       "success",
			handler:    fakeRekorHandler(t, rekorKey),
			checkEntry: true,
		},
		{
			name: "server error returns warning",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal error")) //nolint:errcheck,gosec // test helper
			}),
			wantErr:     true,
			wantWarning: true,
		},
		{
			name: "bad gateway returns warning",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			}),
			wantErr:     true,
			wantWarning: true,
		},
		{
			name: "invalid JSON response returns warning",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte("not json")) //nolint:errcheck,gosec // test helper
			}),
			wantErr:     true,
			wantWarning: true,
		},
		{
			name:        "invalid SET is hard error",
			handler:     invalidSETHandler(),
			wantErr:     true,
			wantWarning: false, // SET failure is hard error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			client := &executor.RekorClient{
				PublicKey: rekorPub,
				HTTP:      srv.Client(),
				URL:       srv.URL,
			}

			rekorJSON, submitErr := client.SubmitHashedRekord(
				context.Background(), hexDigest, sig, pubKeyPEM)

			if tt.wantErr {
				assertRekorError(t, submitErr, tt.wantWarning)
				return
			}

			if submitErr != nil {
				t.Fatalf("unexpected error: %v", submitErr)
			}

			if tt.checkEntry {
				verifyRekorEntry(t, rekorJSON)
			}
		})
	}
}

// assertRekorError verifies that the error is present and has the expected type.
func assertRekorError(t *testing.T, err error, wantWarning bool) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var w *executor.RekorTransientError
	isWarning := errorAs(err, &w)
	if wantWarning && !isWarning {
		t.Errorf("expected RekorTransientError, got: %v", err)
	}
	if !wantWarning && isWarning {
		t.Errorf("expected hard error, got RekorTransientError: %v", err)
	}
}

// verifyRekorEntry checks all fields of a *lane.RekorEntry match the fake response.
func verifyRekorEntry(t *testing.T, entry *lane.RekorEntry) {
	t.Helper()
	if entry == nil {
		t.Fatal("RekorEntry is nil")
	}
	if entry.LogIndex != 42 {
		t.Errorf("LogIndex = %d, want 42", entry.LogIndex)
	}
	wantLogID := strings.Repeat("ab", 32)
	if entry.LogID != wantLogID {
		t.Errorf("LogID = %q, want %s", entry.LogID, wantLogID)
	}
	if entry.IntegratedTime != 1700000000 {
		t.Errorf("IntegratedTime = %d, want 1700000000", entry.IntegratedTime)
	}
	if entry.UUID == "" {
		t.Error("UUID is empty")
	}
	if entry.SignedEntryTimestamp == "" {
		t.Error("SignedEntryTimestamp is empty")
	}
	wantRootHash := strings.Repeat("cc", 32)
	if entry.InclusionProof.RootHash != wantRootHash {
		t.Errorf("RootHash = %q, want %s", entry.InclusionProof.RootHash, wantRootHash)
	}
	if entry.InclusionProof.TreeSize != 100 {
		t.Errorf("TreeSize = %d, want 100", entry.InclusionProof.TreeSize)
	}
	if len(entry.InclusionProof.Hashes) != 3 {
		t.Errorf("Hashes count = %d, want 3", len(entry.InclusionProof.Hashes))
	}
}

func TestParseRekorPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		pem     []byte
		wantErr bool
	}{
		{
			name: "valid ECDSA P-256",
			pem: func() []byte {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			}(),
		},
		{
			name:    "no PEM block",
			pem:     []byte("not a pem"),
			wantErr: true,
		},
		{
			name:    "invalid DER",
			pem:     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad")}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := executor.ParseRekorPublicKey(tt.pem)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if pub.Curve != elliptic.P256() {
				t.Error("expected P-256 curve")
			}
		})
	}
}

func TestSubmitHashedRekord_NetworkTimeout(t *testing.T) {
	// Server that never responds.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		select {} // block forever
	}))
	defer srv.Close()

	_, rekorPubPEM := generateRekorKey(t)
	rekorPub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	sig, pubKeyPEM, hexDigest := generateSignerKey(t)

	client := &executor.RekorClient{
		PublicKey: rekorPub,
		HTTP:      srv.Client(),
		URL:       srv.URL,
	}

	// Use an already-cancelled context to trigger immediate timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, submitErr := client.SubmitHashedRekord(ctx, hexDigest, sig, pubKeyPEM)
	if submitErr == nil {
		t.Fatal("expected error for cancelled context")
	}
	var w *executor.RekorTransientError
	if !errorAs(submitErr, &w) {
		t.Errorf("expected RekorTransientError, got: %T: %v", submitErr, submitErr)
	}
}

func TestSignManifest_WithRekor(t *testing.T) {
	rekorKey, rekorPubPEM := generateRekorKey(t)
	rekorPub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write(fakeRekorResponse(t, rekorKey)) //nolint:errcheck,gosec // test helper
	}))
	defer srv.Close()

	signingKey, signingKeyPEM := generateTestKey(t)
	_ = signingKey

	client := &executor.RekorClient{
		PublicKey: rekorPub,
		HTTP:      srv.Client(),
		URL:       srv.URL,
	}

	digest := testDigest()
	result, signErr := executor.SignManifest(context.Background(), digest, signingKeyPEM, nil, client)
	if signErr != nil {
		t.Fatalf("SignManifest with Rekor: %v", signErr)
	}

	// Verify the OCI image still has the cosign signature annotation.
	manifest, err := result.Image.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Annotations["dev.sigstore.cosign/signature"] == "" {
		t.Error("missing cosign signature annotation")
	}

	// Verify Rekor entry is present and valid.
	if result.Rekor == nil {
		t.Fatal("Rekor is nil")
	}
	if result.Rekor.LogIndex != 42 {
		t.Errorf("LogIndex = %d, want 42", result.Rekor.LogIndex)
	}
}

func TestSignManifest_RekorSkippedWhenNil(t *testing.T) {
	_, signingKeyPEM := generateTestKey(t)

	digest := testDigest()
	result, err := executor.SignManifest(context.Background(), digest, signingKeyPEM, nil, nil)
	if err != nil {
		t.Fatalf("SignManifest without Rekor: %v", err)
	}

	// Rekor should be nil when Rekor is not configured.
	if result.Rekor != nil {
		t.Errorf("expected nil Rekor, got %+v", result.Rekor)
	}

	// OCI image should still be valid with cosign signature.
	manifest, manifestErr := result.Image.Manifest()
	if manifestErr != nil {
		t.Fatal(manifestErr)
	}
	if manifest.Annotations["dev.sigstore.cosign/signature"] == "" {
		t.Error("missing cosign signature annotation")
	}
}

// --------------------------------------------------------------------------.
// SubmitDSSE tests.
// --------------------------------------------------------------------------.

func TestSubmitDSSE(t *testing.T) {
	rekorKey, rekorPubPEM := generateRekorKey(t)
	rekorPub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Fake DSSE envelope and signer public key.
	envelopeJSON := []byte(`{"payloadType":"application/vnd.strike.attestation+json","payload":"dGVzdA","signatures":[]}`)
	_, signerPubPEM := generateTestKey(t)

	tests := []struct {
		handler     http.HandlerFunc
		name        string
		wantErr     bool
		wantWarning bool
		checkEntry  bool
	}{
		{
			name:       "success",
			handler:    fakeDSSERekorHandler(t, rekorKey),
			checkEntry: true,
		},
		{
			name: "server error returns warning",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal error")) //nolint:errcheck,gosec // test helper
			}),
			wantErr:     true,
			wantWarning: true,
		},
		{
			name:        "invalid SET is hard error",
			handler:     invalidSETHandler(),
			wantErr:     true,
			wantWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			client := &executor.RekorClient{
				PublicKey: rekorPub,
				HTTP:      srv.Client(),
				URL:       srv.URL,
			}

			entry, submitErr := client.SubmitDSSE(
				context.Background(), envelopeJSON, signerPubPEM)

			if tt.wantErr {
				assertRekorError(t, submitErr, tt.wantWarning)
				return
			}

			if submitErr != nil {
				t.Fatalf("unexpected error: %v", submitErr)
			}

			if tt.checkEntry {
				verifyRekorEntry(t, entry)
			}
		})
	}
}

// fakeDSSERekorHandler validates the dsse request structure and responds with
// a canned Rekor 201 response.
func fakeDSSERekorHandler(t *testing.T, rekorKey *ecdsa.PrivateKey) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/log/entries" {
			t.Errorf("path = %s, want /api/v1/log/entries", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %s, want application/json", ct)
		}

		var body map[string]any
		if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
			t.Errorf("decode request body: %v", decErr)
		}
		if body["kind"] != "dsse" {
			t.Errorf("kind = %v, want dsse", body["kind"])
		}
		if body["apiVersion"] != "0.0.1" {
			t.Errorf("apiVersion = %v, want 0.0.1", body["apiVersion"])
		}

		spec, ok := body["spec"].(map[string]any)
		if !ok {
			t.Fatal("missing or invalid spec in request body")
		}
		pc, ok := spec["proposedContent"].(map[string]any)
		if !ok {
			t.Fatal("missing or invalid proposedContent in spec")
		}
		if pc["envelope"] == nil {
			t.Error("missing envelope in proposedContent")
		}
		if pc["verifiers"] == nil {
			t.Error("missing verifiers in proposedContent")
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(fakeRekorResponse(t, rekorKey)) //nolint:errcheck,gosec // test helper
	}
}

// errorAs is a type-safe wrapper for errors.As that avoids importing errors
// in every call site (errors is already used via the executor package).
func errorAs[T error](err error, target *T) bool {
	for err != nil {
		if t, ok := err.(T); ok { //nolint:errorlint // generic helper, intentional type assertion
			*target = t
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
