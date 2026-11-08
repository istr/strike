package registry

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// CredentialTransport wraps inner so the declared registry credential rides
// every request to authority, the registry's written authority, as the bearer
// (ADR-058 D2). It is the one place a registry token reaches the wire, for a
// push, for every read of a deploy target inside a run (ADR-058 amendment
// 2026-11-08), and for strike verify's reads of its target (ADR-041
// amendment 2026-11-08): the token stays a SecretString until this round
// tripper writes the header, and go-containerregistry, handed no
// authenticator, sends what this transport sends. A request to any other
// host is refused before it is sent, and so is every request that results
// from following a redirect, on any host: a request carrying the declared
// credential is never redirected.
func CredentialTransport(inner http.RoundTripper, authority string, token lane.SecretString) http.RoundTripper {
	return credentialTransport{inner: inner, token: token, authority: authority}
}

// credentialTransport is the round tripper CredentialTransport returns.
type credentialTransport struct {
	inner     http.RoundTripper
	token     lane.SecretString
	authority string
}

// RoundTrip implements http.RoundTripper. net/http hands a request it created
// by following a redirect the response that caused it; that is the signal the
// refusal keys on. The caller's request is cloned, not modified.
func (t credentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response != nil {
		return nil, fmt.Errorf("registry %s: redirect to %s refused; a request carrying the declared credential is never redirected", t.authority, req.URL.Host)
	}
	if req.URL.Host != t.authority {
		return nil, fmt.Errorf("registry %s: request to %s refused; the declared credential is presented to its own registry only", t.authority, req.URL.Host)
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token.Expose())
	return t.inner.RoundTrip(r)
}

// TargetTransports is what strike verify reads through under a declared
// registry credential (ADR-041 amendment 2026-11-08). A read of the target
// authority resolves through the system resolver, verifies the presented
// chain against the declared anchor, and carries the registry token through
// CredentialTransport, so any redirect of it fails. A read of any other
// registry, a trust root elsewhere included, goes through anonymous, the
// transports every read of verify goes through without a credential.
type TargetTransports struct {
	config    *tls.Config
	anonymous SystemTransports
	token     lane.SecretString
	authority string
}

// NewTargetTransports returns the TargetTransports of a registry token for
// the registry at authority, its written authority, that presents a chain
// anchor verifies; every other registry is read through anonymous.
func NewTargetTransports(authority string, anchor endpoint.Certificate, token lane.SecretString, anonymous SystemTransports) (TargetTransports, error) {
	config, err := transport.BuildTLSConfig(anchor)
	if err != nil {
		return TargetTransports{}, fmt.Errorf("registry %s: %w", authority, err)
	}
	return TargetTransports{config: config, anonymous: anonymous, token: token, authority: authority}, nil
}

// Transport implements Transports.
func (t TargetTransports) Transport(ref primitive.ImageRef) (http.RoundTripper, error) {
	written := string(ref)
	nameRef, err := name.ParseReference(written)
	if err != nil {
		return nil, fmt.Errorf("registry read %s: %w", ref, err)
	}
	if nameRef.Context().RegistryStr() != t.authority {
		return t.anonymous.Transport(ref)
	}
	base := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: t.config}
	return transport.HTTPSOnly(CredentialTransport(base, t.authority, t.token)), nil
}
