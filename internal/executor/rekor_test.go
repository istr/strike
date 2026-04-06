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
	payload := struct {
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
	logID := "deadbeef"
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
				"rootHash": "aabbccdd",
				"treeSize": 100,
				"logIndex": logIndex,
				"hashes":   []string{"1111", "2222", "3333"},
			},
		},
	}

	resp := map[string]any{"test-uuid-123": entry}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

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
		name        string
		handler     http.HandlerFunc
		wantErr     bool
		wantWarning bool
		checkEntry  bool
	}{
		{
			name: "success",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request structure.
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if r.URL.Path != "/api/v1/log/entries" {
					t.Errorf("path = %s, want /api/v1/log/entries", r.URL.Path)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("content-type = %s, want application/json", ct)
				}

				// Verify request body structure.
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
				w.Write(fakeRekorResponse(t, rekorKey)) //nolint:errcheck // test helper
			}),
			checkEntry: true,
		},
		{
			name: "server error returns warning",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal error")) //nolint:errcheck // test helper
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
				w.Write([]byte("not json")) //nolint:errcheck // test helper
			}),
			wantErr:     true,
			wantWarning: true,
		},
		{
			name: "invalid SET is hard error",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				body := base64.StdEncoding.EncodeToString([]byte(`{"kind":"hashedrekord"}`))
				entry := map[string]any{
					"body":           body,
					"integratedTime": 1700000000,
					"logID":          "deadbeef",
					"logIndex":       42,
					"verification": map[string]any{
						"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("bad-sig")),
						"inclusionProof": map[string]any{
							"rootHash": "aabbccdd",
							"treeSize": 100,
							"logIndex": 42,
							"hashes":   []string{"1111"},
						},
					},
				}
				resp := map[string]any{"uuid-bad": entry}
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(resp) //nolint:errcheck // test helper
			}),
			wantErr:     true,
			wantWarning: false, // SET failure is hard error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			client := &executor.RekorClient{
				URL:       srv.URL,
				PublicKey: rekorPub,
				HTTP:      srv.Client(),
			}

			entry, submitErr := client.SubmitHashedRekord(
				context.Background(), hexDigest, sig, pubKeyPEM)

			if tt.wantErr {
				if submitErr == nil {
					t.Fatal("expected error, got nil")
				}
				var w *executor.RekorWarning
				isWarning := false
				if ok := errorAs(submitErr, &w); ok {
					isWarning = true
				}
				if tt.wantWarning && !isWarning {
					t.Errorf("expected RekorWarning, got: %v", submitErr)
				}
				if !tt.wantWarning && isWarning {
					t.Errorf("expected hard error, got RekorWarning: %v", submitErr)
				}
				return
			}

			if submitErr != nil {
				t.Fatalf("unexpected error: %v", submitErr)
			}

			if !tt.checkEntry {
				return
			}

			// Verify entry fields.
			if entry.UUID != "test-uuid-123" {
				t.Errorf("UUID = %q, want test-uuid-123", entry.UUID)
			}
			if entry.LogIndex != 42 {
				t.Errorf("LogIndex = %d, want 42", entry.LogIndex)
			}
			if entry.LogID != "deadbeef" {
				t.Errorf("LogID = %q, want deadbeef", entry.LogID)
			}
			if entry.IntegratedTime != 1700000000 {
				t.Errorf("IntegratedTime = %d, want 1700000000", entry.IntegratedTime)
			}
			if entry.InclusionProof == nil {
				t.Fatal("InclusionProof is nil")
			}
			if entry.InclusionProof.RootHash != "aabbccdd" {
				t.Errorf("RootHash = %q, want aabbccdd", entry.InclusionProof.RootHash)
			}
			if entry.InclusionProof.TreeSize != 100 {
				t.Errorf("TreeSize = %d, want 100", entry.InclusionProof.TreeSize)
			}
			if len(entry.InclusionProof.Hashes) != 3 {
				t.Errorf("Hashes count = %d, want 3", len(entry.InclusionProof.Hashes))
			}
		})
	}
}

func TestRekorAnnotations(t *testing.T) {
	entry := &executor.RekorEntry{
		UUID:                "uuid-1",
		LogIndex:            99,
		LogID:               "aabb",
		IntegratedTime:      1700000001,
		SignedEntryTimestamp: []byte("fake-set"),
		InclusionProof: &executor.InclusionProof{
			RootHash: "ccdd",
			TreeSize: 200,
			LogIndex: 99,
			Hashes:   []string{"h1", "h2"},
		},
	}

	ann := entry.Annotations()

	tests := []struct {
		key  string
		want string
	}{
		{"rekor.logIndex", "99"},
		{"rekor.logID", "aabb"},
		{"rekor.integratedTime", "1700000001"},
		{"rekor.signedEntryTimestamp", base64.StdEncoding.EncodeToString([]byte("fake-set"))},
		{"rekor.inclusionProof.rootHash", "ccdd"},
		{"rekor.inclusionProof.treeSize", "200"},
		{"rekor.inclusionProof.logIndex", "99"},
		{"rekor.inclusionProof.hashes", "h1,h2"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := ann[tt.key]
			if !ok {
				t.Fatalf("annotation %q not found", tt.key)
			}
			if got != tt.want {
				t.Errorf("annotation %q = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestRekorAnnotations_NoInclusionProof(t *testing.T) {
	entry := &executor.RekorEntry{
		LogIndex:            1,
		LogID:               "aa",
		IntegratedTime:      1,
		SignedEntryTimestamp: []byte("s"),
	}

	ann := entry.Annotations()

	for key := range ann {
		if strings.HasPrefix(key, "rekor.inclusionProof.") {
			t.Errorf("unexpected inclusion proof annotation: %s", key)
		}
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {} // block forever
	}))
	defer srv.Close()

	rekorKey, rekorPubPEM := generateRekorKey(t)
	_ = rekorKey
	rekorPub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	sig, pubKeyPEM, hexDigest := generateSignerKey(t)

	client := &executor.RekorClient{
		URL:       srv.URL,
		PublicKey: rekorPub,
		HTTP:      srv.Client(),
	}

	// Use an already-cancelled context to trigger immediate timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, submitErr := client.SubmitHashedRekord(ctx, hexDigest, sig, pubKeyPEM)
	if submitErr == nil {
		t.Fatal("expected error for cancelled context")
	}
	var w *executor.RekorWarning
	if !errorAs(submitErr, &w) {
		t.Errorf("expected RekorWarning, got: %T: %v", submitErr, submitErr)
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
		w.Write(fakeRekorResponse(t, rekorKey)) //nolint:errcheck // test helper
	}))
	defer srv.Close()

	signingKey, signingKeyPEM := generateTestKey(t)
	_ = signingKey

	client := &executor.RekorClient{
		URL:       srv.URL,
		PublicKey: rekorPub,
		HTTP:      srv.Client(),
	}

	digest := testDigest()
	img, signErr := executor.SignManifest(context.Background(), digest, signingKeyPEM, nil, client)
	if signErr != nil {
		t.Fatalf("SignManifest with Rekor: %v", signErr)
	}

	manifest, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}

	// Verify Rekor annotations are present.
	rekorKeys := []string{
		"rekor.logIndex",
		"rekor.logID",
		"rekor.integratedTime",
		"rekor.signedEntryTimestamp",
		"rekor.inclusionProof.rootHash",
		"rekor.inclusionProof.treeSize",
		"rekor.inclusionProof.logIndex",
		"rekor.inclusionProof.hashes",
	}
	for _, key := range rekorKeys {
		if _, ok := manifest.Annotations[key]; !ok {
			t.Errorf("missing annotation %q", key)
		}
	}

	// Verify the cosign signature annotation is still present.
	if manifest.Annotations["dev.sigstore.cosign/signature"] == "" {
		t.Error("missing cosign signature annotation")
	}
}

func TestSignManifest_RekorSkippedWhenNil(t *testing.T) {
	_, signingKeyPEM := generateTestKey(t)

	digest := testDigest()
	img, err := executor.SignManifest(context.Background(), digest, signingKeyPEM, nil, nil)
	if err != nil {
		t.Fatalf("SignManifest without Rekor: %v", err)
	}

	manifest, manifestErr := img.Manifest()
	if manifestErr != nil {
		t.Fatal(manifestErr)
	}

	// No Rekor annotations should be present.
	for key := range manifest.Annotations {
		if strings.HasPrefix(key, "rekor.") {
			t.Errorf("unexpected rekor annotation: %s", key)
		}
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
