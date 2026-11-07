package transport

import "net/http"

// HTTPSOnly wraps inner so every request is rewritten onto the https scheme
// before it reaches the dial layer. go-containerregistry resolves a
// localhost-style registry name to the http scheme on its own; a registry
// connection strike opens owns its addressing (ADR-051 D4), so the scheme is
// pinned here and the plaintext dial below it stays a structurally
// unreachable rejection.
func HTTPSOnly(inner http.RoundTripper) http.RoundTripper {
	return httpsOnlyTransport{inner: inner}
}

// httpsOnlyTransport is the round tripper HTTPSOnly returns.
type httpsOnlyTransport struct {
	inner http.RoundTripper
}

// RoundTrip implements http.RoundTripper. The caller's request is cloned, not
// modified.
func (t httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL.Scheme = "https"
	return t.inner.RoundTrip(r)
}
