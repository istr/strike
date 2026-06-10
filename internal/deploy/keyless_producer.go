package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/istr/strike/internal/lane"
)

// ambientIDToken reads the OIDC identity token from the environment
// (ADR-040 D-3b-4): the operator or CI injects a short-lived identity
// token via SIGSTORE_ID_TOKEN; strike never runs an interactive flow.
func ambientIDToken() (string, error) {
	tok := os.Getenv("SIGSTORE_ID_TOKEN")
	if tok == "" {
		return "", errors.New("keyless: SIGSTORE_ID_TOKEN is not set")
	}
	return tok, nil
}

// subjectFromIDToken extracts the subject Fulcio binds into the leaf
// certificate: the email claim if present, else sub. The token is NOT
// verified here -- Fulcio verifies it against the issuer; the subject is
// needed client-side only for the proof of possession.
func subjectFromIDToken(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return "", errors.New("keyless: malformed identity token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("keyless: decode token payload: %w", err)
	}
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("keyless: parse token claims: %w", err)
	}
	if claims.Email != "" {
		return claims.Email, nil
	}
	if claims.Sub != "" {
		return claims.Sub, nil
	}
	return "", errors.New("keyless: token has neither email nor sub claim")
}

// produceKeylessBundles runs the keyless chain for a set of projected
// in-toto statements: one ephemeral P-256 key and one Fulcio certificate
// for the set, then per statement DSSE sign -> RFC3161 timestamp ->
// Rekor v2 inclusion -> sigstore v0.3 bundle. Every failure is fatal
// (fail-closed, ADR-040 D-3b-2): a statement that cannot obtain a
// certificate, a timestamp, or an inclusion proof yields an error, never a
// partial bundle. Returned bundles are positionally aligned with
// statements.
func produceKeylessBundles(ctx context.Context, eps lane.KeylessEndpoints, idToken string, statements [][]byte) ([][]byte, error) {
	if len(statements) == 0 {
		return nil, errors.New("keyless: no statements")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keyless: generate ephemeral key: %w", err)
	}
	leafDER, err := fulcioCertificate(ctx, eps.Fulcio, idToken, key)
	if err != nil {
		return nil, err
	}
	bundles := make([][]byte, len(statements))
	for i, stmt := range statements {
		env, sig, err := signStatementKeyless(stmt, key)
		if err != nil {
			return nil, fmt.Errorf("keyless: statement %d: %w", i, err)
		}
		rfc3161, err := tsaTimestamp(ctx, eps.TSA, sig)
		if err != nil {
			return nil, fmt.Errorf("keyless: statement %d: %w", i, err)
		}
		pae := PAEEncode(InTotoPayloadType, stmt)
		paeDigest := sha256.Sum256(pae)
		tle, err := rekorSubmitKeyless(ctx, eps.Rekor, paeDigest[:], sig, leafDER)
		if err != nil {
			return nil, fmt.Errorf("keyless: statement %d: %w", i, err)
		}
		b, err := assembleKeylessBundle(env, leafDER, tle, rfc3161)
		if err != nil {
			return nil, fmt.Errorf("keyless: statement %d: %w", i, err)
		}
		bundles[i] = b
	}
	return bundles, nil
}
