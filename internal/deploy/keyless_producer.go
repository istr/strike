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
	"slices"
	"strings"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
	"github.com/istr/strike/internal/verify"
	"github.com/istr/strike/internal/wire"
)

// tokenMaxLifetime bounds exp - iat of every identity token a deploy reads,
// the builder token and the registry token, in seconds (ADR-058 D4).
const tokenMaxLifetime = 15 * 60

// readIDToken reads the identity token the named entry of secrets delivers,
// resolving a file:// source through root, and decodes its claims,
// fail-closed: a token whose lifetime, exp - iat, is not positive or exceeds
// tokenMaxLifetime is refused before any use (ADR-058 D4). The token is not
// verified here; the peer it is minted for verifies it.
func readIDToken(secrets map[primitive.Identifier]lane.SecretSource, root *os.Root, name primitive.Identifier) (lane.SecretString, idTokenClaims, error) {
	token, err := lane.ReadSecret(secrets[name], root)
	if err != nil {
		return lane.SecretString{}, idTokenClaims{}, err
	}
	claims, err := checkIDToken(token)
	if err != nil {
		return lane.SecretString{}, idTokenClaims{}, err
	}
	return token, claims, nil
}

// checkIDToken decodes the claims of an identity token and refuses it,
// fail-closed, when its lifetime, exp - iat, is not positive or exceeds
// tokenMaxLifetime (ADR-058 D4).
func checkIDToken(token lane.SecretString) (idTokenClaims, error) {
	claims, err := decodeIDTokenClaims(token)
	if err != nil {
		return idTokenClaims{}, err
	}
	if claims.Iat <= 0 || claims.Exp <= claims.Iat {
		return idTokenClaims{}, errors.New("token carries no valid iat and exp")
	}
	if lifetime := claims.Exp - claims.Iat; lifetime > tokenMaxLifetime {
		return idTokenClaims{}, fmt.Errorf("token lifetime %ds exceeds the %ds bound", lifetime, tokenMaxLifetime)
	}
	return claims, nil
}

// CheckRegistryToken checks a registry token before any use, fail-closed:
// its lifetime stays within the bound, and, when oidcAudience is not empty,
// its audience does not contain it, because a token minted for Fulcio is
// never presented to a registry (ADR-058 D3, D4, amendment 2026-11-08). The
// lane run and strike verify check every registry token through it; each
// reads the token its own way.
func CheckRegistryToken(token lane.SecretString, oidcAudience string) error {
	claims, err := checkIDToken(token)
	if err != nil {
		return err
	}
	if oidcAudience != "" && slices.Contains(claims.Aud, oidcAudience) {
		return fmt.Errorf("its audience contains the oidc audience %q, and a token minted for Fulcio is never presented to a registry", oidcAudience)
	}
	return nil
}

// builderToken reads the builder's identity token from the lane secret the
// oidc block names and checks it before any Fulcio contact, fail-closed: its
// lifetime stays within the bound (readIDToken), and its issuer is the
// lane-declared issuer. The identity is checked on the certificate Fulcio
// issues, before the first signature, because claim names differ per
// provider and the certificate is what the verifier sees (ADR-041 decision 6
// as amended by ADR-057 D2). strike never runs an interactive flow.
func (d *Deployer) builderToken() (lane.SecretString, error) {
	token, claims, err := readIDToken(d.Lane.Secrets, d.LaneRoot, d.OIDC.Token)
	if err != nil {
		return lane.SecretString{}, fmt.Errorf("keyless: oidc token %q: %w", d.OIDC.Token, err)
	}
	if claims.Iss != d.OIDC.Issuer.URL() {
		return lane.SecretString{}, fmt.Errorf("keyless: token issuer %q does not match the lane-declared issuer %q", claims.Iss, d.OIDC.Issuer.URL())
	}
	return token, nil
}

// idTokenClaims are the identity-token claims strike reads before any use:
// the lifetime for the bound, the issuer for the builder token's pre-check,
// the audience for the registry token's, and the subject the proof of
// possession signs.
type idTokenClaims struct {
	Email string   `json:"email"`
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   audience `json:"aud"`
	Exp   int64    `json:"exp"`
	Iat   int64    `json:"iat"`
}

// audience is the JWT aud claim, which RFC 7519 section 4.1.3 admits as one
// string or as an array of strings.
type audience []string

// UnmarshalJSON decodes either form of the claim.
func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("aud claim: %w", err)
	}
	*a = many
	return nil
}

// decodeIDTokenClaims decodes the payload of the identity token. The token is
// NOT verified here -- the peer it is minted for verifies it; the claims are
// needed client-side only.
func decodeIDTokenClaims(idToken lane.SecretString) (idTokenClaims, error) {
	parts := strings.Split(idToken.Expose(), ".")
	if len(parts) < 2 {
		return idTokenClaims{}, errors.New("malformed identity token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("decode token payload: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idTokenClaims{}, fmt.Errorf("parse token claims: %w", err)
	}
	return claims, nil
}

// subjectFromIDToken extracts the subject the proof of possession signs: the
// email claim if present, else sub.
func subjectFromIDToken(idToken lane.SecretString) (string, error) {
	claims, err := decodeIDTokenClaims(idToken)
	if err != nil {
		return "", fmt.Errorf("keyless: %w", err)
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
// must bind the identity, issuer and extension pins oidc declares before the
// first signature (ADR-041 decision 6 as amended by ADR-057 D2). Every
// failure is fatal
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
	if idErr := verify.Identity(leaf, oidc.Identity, oidc.Issuer, &oidc.Extensions); idErr != nil {
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
