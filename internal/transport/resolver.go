package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

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
			return DialVerified(ctx, string(decl.Host), decl.Trust)
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
		return nil, fmt.Errorf("transport: lookup %q via %s: %w", name, decl.Host, err)
	}
	return addrs, nil
}

// ProbeResolver performs a one-shot DNS-over-TLS roundtrip
// against the declared resolver, used as a pre-flight check at
// strike run start. The probe target is an NS query on "." (the
// root zone), which every standards-compliant DoT resolver
// answers; this avoids encoding any provider-specific sanity
// name.
//
// The probe verifies, in one round trip:
//   - the resolver's TLS endpoint is reachable on the declared port
//   - the declared trust anchor (fingerprint or CA bundle) matches
//     the certificate the resolver presents at this moment
//   - the resolver responds to DNS queries over the established
//     TLS connection
//
// The probe is operational, not attested. Per-query DNS
// resolutions that DO feed deploy attestation are introduced in
// PR-19 (allowlist resolver).
//
// Probe placement: see docs/ROADMAP-ADR-028.md D16. The probe
// runs at strike run time, after lane.Parse, not in lane.Parse,
// because probe outcome is an environmental property and
// lane.Parse must stay an offline check of input properties.
func ProbeResolver(ctx context.Context, decl DNSResolver) error {
	if _, err := dotResolver(decl).LookupNS(ctx, "."); err != nil {
		clearMisleadingServerField(err)
		return fmt.Errorf("transport: resolver probe via %s: %w", decl.Host, err)
	}
	return nil
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
