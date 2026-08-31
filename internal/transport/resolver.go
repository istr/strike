package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// identityCapture collects the ConnectionIdentity observed by a
// net.Resolver Dial callback. The Go resolver may invoke Dial more
// than once (retry, dual-stack); for DoT the dial target is always
// the single declared resolver, so repeats observe the same
// identity. The capture keeps the first non-empty identity and is
// mutex-guarded for race-cleanliness under concurrent dials.
type identityCapture struct {
	id  ConnectionIdentity
	mu  sync.Mutex
	set bool
}

func (c *identityCapture) record(id ConnectionIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set {
		c.id = id
		c.set = true
	}
}

func (c *identityCapture) get() (ConnectionIdentity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id, c.set
}

// dialResolver opens the verified TLS connection to the declared DoT
// endpoint. The declared host is an address literal -- lane validation
// rejects an FQDN, because the resolver is the lane's own resolution
// authority -- so it is both the routing destination and the identity the
// certificate is verified against, and no name is resolved to reach the
// resolver. A host that does not parse is an error rather than a fallback:
// it means the value reached the dialer without validation.
func (d *Dialer) dialResolver(ctx context.Context) (*VerifiedConn, error) {
	host := d.resolver.Address.Host
	addr, err := netip.ParseAddr(host.String())
	if err != nil {
		return nil, fmt.Errorf("transport: resolver host %q is not an address literal: %w", host, err)
	}
	p := d.resolver.Address.Port
	if p == nil || *p < 1 || *p > 65535 {
		return nil, fmt.Errorf("transport: resolver %s: a port in 1..65535 is required", d.resolver.Address.Authority())
	}
	dialPort := uint16(*p)
	return DialResolved(ctx, netip.AddrPortFrom(addr, dialPort), host, d.resolver.Trust)
}

// dotResolver builds a net.Resolver whose dial path goes
// through the declared DoT endpoint via DialResolved. The
// PreferGo flag forces Go's in-process resolver, which is the
// only path that honours the custom Dial; the libc-backed path
// would ignore it.
//
// The Dial function ignores the requested network (Go's resolver
// may ask for "udp" or "tcp") and always establishes a TLS
// connection to the DoT endpoint. DoT is TCP-DNS over TLS
// (RFC 7858); the TLS connection satisfies both network types
// from the resolver's perspective because the wire format (DNS
// length-prefixed messages) is the same.
func (d *Dialer) dotResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			vc, err := d.dialResolver(ctx)
			if err != nil {
				return nil, err
			}
			return vc.Conn(), nil
		},
	}
}

// clearMisleadingServerField clears net.DNSError.Server on any
// DNSError found in the error chain. Go's net.Resolver populates
// that field from /etc/resolv.conf even when a custom Dial is in
// effect, producing error text like "lookup foo on 10.70.10.1:53"
// that names a system-DNS address the query never actually went
// to. The declared DoT endpoint is already named in the caller's
// outer error wrapper; clearing this inner field removes the
// misleading /etc/resolv.conf reference from operator-facing
// output without otherwise altering the error chain.
//
// errors.As traverses the chain and assigns a pointer to the
// concrete *net.DNSError; mutating Server through that pointer
// mutates the original instance in the chain.
func clearMisleadingServerField(err error) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		dnsErr.Server = ""
	}
}
