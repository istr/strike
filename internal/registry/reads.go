package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// Transports hands out the round tripper a read of one image reference goes
// through. A lane run reads through the registries it declares (Reads);
// strike verify, which declares nothing, reads through the system resolver
// and roots (SystemTransports).
type Transports interface {
	Transport(ref primitive.ImageRef) (http.RoundTripper, error)
}

// SystemTransports reads anonymously through the system resolver. With Roots
// nil it reads through go-containerregistry's default transport and the
// system roots, which is how strike verify reads without a registry token;
// a lane run never does (ADR-029 amendment 2026-11-06, ADR-041 amendment
// 2026-11-08). Roots, when set, replaces the system roots as the roots every
// chain is verified against. Production leaves it nil; a test sets it to a
// local CA its registry chains to, so the anonymous path runs over TLS
// without that CA in the system store.
type SystemTransports struct {
	Roots *x509.CertPool
}

// Transport implements Transports.
func (s SystemTransports) Transport(primitive.ImageRef) (http.RoundTripper, error) {
	if s.Roots == nil {
		return remote.DefaultTransport, nil
	}
	return &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: s.Roots, MinVersion: tls.VersionTLS12},
	}, nil
}

// Reads is the registry read capability of one lane run (ADR-029 amendment
// 2026-11-06). A read reaches only the registry its reference names, which
// the lane declares in registries or as a deploy target, and the storages
// that registry redirects blob reads to. Every connection resolves through
// the run's DoT resolver and verifies against the declared anchor of the host
// it reaches. A read connection's identity is not recorded: the digest pin
// carries the integrity (ADR-030 amendment 2026-11-06). A read of a deploy
// target's authority carries that target's registry token (ADR-058 amendment
// 2026-11-08).
type Reads struct {
	dialer     *transport.Dialer
	registries map[string]lane.Registry
	tokens     map[string]lane.SecretString
}

// NewReads collects the lane's registry declarations by written authority. A
// deploy target counts as a registry without storages; tokens holds the
// registry token of each deploy target's authority, read once when the run
// starts. Lane validation keeps every registry and storage authority unique,
// and the deploy targets of one authority on one anchor and one token, so no
// declaration shadows another.
func NewReads(dialer *transport.Dialer, p *lane.Lane, tokens map[string]lane.SecretString) *Reads {
	registries := make(map[string]lane.Registry, len(p.Registries))
	for _, r := range p.Registries {
		registries[string(r.Registry.Address.Authority())] = r
	}
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		if reg, ok := s.Deploy.Method.(lane.DeployRegistry); ok {
			t := reg.Target
			registries[string(t.Address.Authority())] = lane.Registry{
				Registry: endpoint.TLS{Type: t.Type, Address: t.Address, Trust: t.Trust},
			}
		}
	}
	return &Reads{dialer: dialer, registries: registries, tokens: tokens}
}

// Transport returns the round tripper a read of ref goes through. It admits a
// request to the registry ref names, and a request to one of that registry's
// storages only on a redirect chain that began with a blob GET of the
// registry; every other request fails before it is dialed, a token realm on
// another host included (go-containerregistry itself refuses a realm on a
// private, link-local or loopback IP literal before any request, ahead of
// this policy). Requests leave on https only. A read of a deploy target's
// authority carries its registry token through CredentialTransport, so any
// redirect of it fails.
func (r *Reads) Transport(ref primitive.ImageRef) (http.RoundTripper, error) {
	if r.dialer == nil {
		return nil, errors.New("registry read: dialer required")
	}
	written := string(ref)
	nameRef, err := name.ParseReference(written)
	if err != nil {
		return nil, fmt.Errorf("registry read %s: %w", ref, err)
	}
	authority := nameRef.Context().RegistryStr()
	reg, ok := r.registries[authority]
	if !ok {
		return nil, fmt.Errorf("registry read %s: registry %s is not declared", ref, authority)
	}
	storages := make(map[string]bool, len(reg.Storages))
	for _, s := range reg.Storages {
		storages[string(s.Address.Authority())] = true
	}
	var rt http.RoundTripper = readPolicy{
		inner:    r.dialTransport(authority, append([]endpoint.TLS{reg.Registry}, reg.Storages...)),
		storages: storages,
		registry: authority,
	}
	if token, ok := r.tokens[authority]; ok {
		rt = CredentialTransport(rt, authority, token)
	}
	return transport.HTTPSOnly(rt), nil
}

// dialTransport opens every connection through the run's dialer: the dialed
// authority must be one of hosts, and the connection verifies against that
// host's declared anchor. A plaintext dial is rejected outright.
func (r *Reads) dialTransport(authority string, hosts []endpoint.TLS) *http.Transport {
	anchors := make(map[string]endpoint.TLS, len(hosts))
	for _, h := range hosts {
		if h.Address.Port == nil {
			port := primitive.Port(443)
			h.Address.Port = &port
		}
		anchors[string(h.Address.Authority())] = h
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, ok := anchors[addr]
			if !ok {
				return nil, fmt.Errorf("registry read: dial %q outside registry %s and its storages rejected", addr, authority)
			}
			vc, err := r.dialer.DialPeer(ctx, h.Address.Host, *h.Address.Port, h.Trust)
			if err != nil {
				return nil, err
			}
			return vc.Conn(), nil
		},
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("registry read: plaintext dial to %q rejected; registry reads are https-only", addr)
		},
	}
}

// readPolicy admits a request to the registry, and a request to one of its
// storages only on a redirect chain that began with a blob GET of the
// registry. The response that caused a redirect rides on the redirected
// request, so the chain is walked back to its origin.
type readPolicy struct {
	inner    http.RoundTripper
	storages map[string]bool
	registry string
}

// RoundTrip implements http.RoundTripper.
func (p readPolicy) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if host == p.registry || (p.storages[host] && blobRedirect(req, p.registry)) {
		return p.inner.RoundTrip(req)
	}
	return nil, fmt.Errorf("registry read: request to %s is neither registry %s nor a blob redirect of it to one of its storages", host, p.registry)
}

// blobRedirect reports whether req is a redirect hop whose chain began with a
// GET of a blob of the registry at authority.
func blobRedirect(req *http.Request, authority string) bool {
	origin := req
	for origin.Response != nil && origin.Response.Request != nil {
		origin = origin.Response.Request
	}
	return origin != req && origin.Method == http.MethodGet && origin.URL.Host == authority && isBlobPath(origin.URL.Path)
}

// isBlobPath reports whether path addresses a blob by digest, as
// /v2/<name>/blobs/<digest>.
func isBlobPath(path string) bool {
	parts := strings.Split(path, "/")
	n := len(parts)
	if n < 5 || parts[0] != "" || parts[1] != "v2" || parts[n-2] != "blobs" {
		return false
	}
	_, err := v1.NewHash(parts[n-1])
	return err == nil
}
