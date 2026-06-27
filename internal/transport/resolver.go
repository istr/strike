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

// dotResolver builds a net.Resolver whose dial path goes
// through the declared DoT endpoint via DialVerified. The
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
func dotResolver(decl DNSResolver) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return DialVerified(ctx, decl.Address.Authority(), decl.Trust)
		},
	}
}

// LookupHost resolves a hostname to its A and AAAA addresses via
// the declared DoT resolver. Stateless: each call opens a fresh
// TLS connection. Returns the addresses the resolver answered
// with, in the order received.
//
// PR-17 introduces this function as the building block for the
// pre-flight ProbeResolver; PR-19 will consume it from the
// allowlist resolver for every authorized per-step DNS query.
func LookupHost(ctx context.Context, decl DNSResolver, name string) ([]netip.Addr, error) {
	addrs, err := dotResolver(decl).LookupNetIP(ctx, "ip", name)
	if err != nil {
		clearMisleadingServerField(err)
		return nil, fmt.Errorf("transport: lookup %q via %s: %w", name, decl.Address.Authority(), err)
	}
	return addrs, nil
}

// ProbeResolver performs a one-shot DNS-over-TLS roundtrip against
// the declared resolver, used as a pre-flight check at strike run
// start, and returns the ConnectionIdentity observed at the TLS
// handshake. The probe target is an NS query on "." (the root
// zone), which every standards-compliant DoT resolver answers; this
// avoids encoding any provider-specific sanity name.
//
// The probe verifies, in one round trip:
//   - the resolver's TLS endpoint is reachable on the declared port
//   - the declared trust anchor (fingerprint or CA bundle) matches
//     the certificate the resolver presents at this moment
//   - the resolver responds to DNS queries over the established
//     TLS connection
//
// The returned identity is the observed resolver identity from this
// handshake. Per ADR-030 it is recorded in the deploy attestation:
// DNS has no content anchor, so the resolver's channel identity is
// part of the trust chain. The trust anchor was already enforced by
// DialVerified during this same handshake; the returned identity is
// what that verified handshake observed.
//
// Probe placement: see docs/ADR-028-step-container-egress-mediation.md,
// "Operational requirement: a reachable DoT resolver". The probe runs
// at strike run time, after lane.Parse, not in lane.Parse, because
// probe outcome is an environmental property and lane.Parse must
// stay an offline check of input properties.
func ProbeResolver(ctx context.Context, decl DNSResolver) (ConnectionIdentity, error) {
	var ic identityCapture
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := DialVerified(ctx, decl.Address.Authority(), decl.Trust)
			if err != nil {
				return nil, err
			}
			ic.record(conn.Identity())
			return conn, nil
		},
	}
	if _, err := r.LookupNS(ctx, "."); err != nil {
		clearMisleadingServerField(err)
		return ConnectionIdentity{}, fmt.Errorf("transport: resolver probe via %s: %w", decl.Address.Authority(), err)
	}
	id, ok := ic.get()
	if !ok {
		return ConnectionIdentity{}, fmt.Errorf("transport: resolver probe via %s: no TLS identity captured", decl.Address.Authority())
	}
	return id, nil
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
