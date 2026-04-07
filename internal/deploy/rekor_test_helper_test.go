package deploy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/istr/strike/internal/executor"
)

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
	body := base64.StdEncoding.EncodeToString([]byte(`{"kind":"dsse"}`))
	logID := strings.Repeat("ab", 32)
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
				"hashes":   []string{strings.Repeat("11", 32), strings.Repeat("22", 32)},
			},
		},
	}

	resp := map[string]any{"dsse-uuid-123": entry}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fakeDSSERekorHandler returns an HTTP handler that responds with a valid Rekor
// dsse entry response.
func fakeDSSERekorHandler(t *testing.T, rekorKey *ecdsa.PrivateKey) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}

		var body map[string]any
		if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
			t.Errorf("decode request body: %v", decErr)
		}
		if body["kind"] != "dsse" {
			t.Errorf("kind = %v, want dsse", body["kind"])
		}

		w.WriteHeader(http.StatusCreated)
		w.Write(fakeRekorResponse(t, rekorKey)) //nolint:errcheck,gosec // test helper
	}
}

// newRekorClient constructs a RekorClient for testing with the given server.
func newRekorClient(t *testing.T, rekorPubPEM []byte, srv *http.Client, url string) *executor.RekorClient {
	t.Helper()
	rekorPub, err := executor.ParseRekorPublicKey(rekorPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &executor.RekorClient{
		PublicKey: rekorPub,
		HTTP:      srv,
		URL:       url,
	}
}
