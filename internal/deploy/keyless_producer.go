package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/transport"
	"github.com/istr/strike/internal/verify"
	"github.com/istr/strike/internal/wire"
)

// ambientIDToken reads the OIDC identity token from the environment
// (ADR-040 D-3b-4): the operator or CI injects a short-lived identity
// token via SIGSTORE_ID_TOKEN; strike never runs an interactive flow.
func ambientIDToken() (lane.SecretString, error) {
	tok := os.Getenv("SIGSTORE_ID_TOKEN")
	if tok == "" {
		return lane.SecretString{}, errors.New("keyless: SIGSTORE_ID_TOKEN is not set")
	}
	return lane.NewSecretString(tok), nil
}

// idTokenClaims are the identity-token claims strike reads before any Fulcio
// contact: the issuer for the fail-closed pre-check, and the subject the proof
// of possession signs.
type idTokenClaims struct {
	Email string `json:"email"`
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
}

// decodeIDTokenClaims decodes the payload of the identity token. The token is
// NOT verified here -- Fulcio verifies it against the issuer; the claims are
// needed client-side only.
func decodeIDTokenClaims(idToken lane.SecretString) (idTokenClaims, error) {
	parts := strings.Split(idToken.Expose(), ".")
	if len(parts) < 2 {
		return idTokenClaims{}, errors.New("keyless: malformed identity token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("keyless: decode token payload: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idTokenClaims{}, fmt.Errorf("keyless: parse token claims: %w", err)
	}
	return claims, nil
}

// subjectFromIDToken extracts the subject the proof of possession signs: the
// email claim if present, else sub.
func subjectFromIDToken(idToken lane.SecretString) (string, error) {
	claims, err := decodeIDTokenClaims(idToken)
	if err != nil {
		return "", err
	}
	if claims.Email != "" {
		return claims.Email, nil
	}
	if claims.Sub != "" {
		return claims.Sub, nil
	}
	return "", errors.New("keyless: token has neither email nor sub claim")
}

// ProduceKeylessBundles runs the keyless chain for a set of projected
// in-toto statements: one ephemeral P-256 key and one Fulcio certificate
// for the set, then per statement DSSE sign -> RFC3161 timestamp ->
// Rekor v2 inclusion -> sigstore v0.3 bundle. The certificate Fulcio issued
// must bind the identity and issuer oidc declares before the first signature
// (ADR-041 decision 6 as amended by ADR-057 D2). Every failure is fatal
// (fail-closed, ADR-040 D-3b-2): a statement that cannot obtain a
// certificate, a timestamp, or an inclusion proof yields an error, never a
// partial bundle. Returned bundles are positionally aligned with
// statements. The endpoints are reached through dialer, so they resolve by
// the lane's declared resolver like every other declared peer.
func ProduceKeylessBundles(ctx context.Context, eps lane.KeylessEndpoints, dialer *transport.Dialer, idToken lane.SecretString, oidc lane.OIDCConfig, statements [][]byte) ([][]byte, error) {
	if len(statements) == 0 {
		return nil, errors.New("keyless: no statements")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keyless: generate ephemeral key: %w", err)
	}
	leafDER, err := fulcioCertificate(ctx, eps.Fulcio, dialer, idToken, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("keyless: parse issued certificate: %w", err)
	}
	if idErr := verify.Identity(leaf, oidc.Identity, oidc.Issuer); idErr != nil {
		return nil, fmt.Errorf("keyless: issued certificate: %w", idErr)
	}
	bundles := make([][]byte, len(statements))
	for i, stmt := range statements {
		env, sig, err := signStatementKeyless(stmt, key)
		if err != nil {
			return nil, fmt.Errorf("keyless: statement %d: %w", i, err)
		}
		rfc3161, err := tsaTimestamp(ctx, eps.TSA, dialer, sig)
		if err != nil {
			return nil, fmt.Errorf("keyless: statement %d: %w", i, err)
		}
		pae := wire.PAEEncode(wire.PayloadType, stmt)
		paeDigest := sha256.Sum256(pae)
		tle, err := rekorSubmitKeyless(ctx, eps.Rekor, dialer, paeDigest[:], sig, leafDER)
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
