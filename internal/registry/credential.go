package registry

import (
	"fmt"
	"net/http"

	"github.com/istr/strike/internal/lane"
)

// CredentialTransport wraps inner so the declared registry credential rides
// every request to authority, the registry's written authority, as the bearer
// (ADR-058 D2). It is the one place a registry token reaches the wire, for a
// push and for every read of a deploy target inside a run (ADR-058 amendment
// 2026-11-08): the token stays a SecretString until this round tripper writes
// the header, and go-containerregistry, handed no authenticator, sends what
// this transport sends. A request to any other host is refused before it is
// sent, and so is every request that results from following a redirect, on
// any host: a request carrying the declared credential is never redirected.
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
