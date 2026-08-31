package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// Dialer owns the resolved-and-verified dial for one lane run: it resolves
// a name through the lane's declared DoT resolver, dials the address that
// resolver answered with, and verifies the presented certificate against
// the declared name. It also probes the resolver itself, so the pre-flight
// check and every later dial travel the same path.
//
// It is a value with a named contract rather than an anonymous closure
// because a closure is what the capability looked like when the packages
// that needed it could not import the package that knows how names
// resolve. That package is this one, and it sits below every consumer in
// the tier order, so the capability can be the type itself and the
// indirection disappears with it.
//
// The zero value is not usable; construct with NewDialer. A Dialer is safe
// for concurrent use: it holds only the declaration, and each call opens
// its own connection.
type Dialer struct {
	resolver endpoint.TLS
}

// NewDialer returns a Dialer that resolves through the declared DoT
// endpoint. The declaration must name a host; lane validation additionally
// requires that host to be an address literal, since the resolver is the
// lane's resolution authority and cannot resolve its own name.
func NewDialer(resolver endpoint.TLS) (*Dialer, error) {
	if resolver.Address.Host == "" {
		return nil, errors.New("transport: dialer requires a declared resolver host")
	}
	return &Dialer{resolver: resolver}, nil
}

// LookupHost resolves a hostname to its A and AAAA addresses via the
// declared DoT resolver. Stateless: each call opens a fresh TLS
// connection. Returns the addresses the resolver answered with, in the
// order received.
func (d *Dialer) LookupHost(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, err := d.dotResolver().LookupNetIP(ctx, "ip", name)
	if err != nil {
		clearMisleadingServerField(err)
		return nil, fmt.Errorf("transport: lookup %q via %s: %w", name, d.resolver.Address.Authority(), err)
	}
	return addrs, nil
}

// DialPeer resolves name through the declared DoT resolver and opens a
// verified TLS connection to the first address answered, verifying the
// presented certificate against name itself. Routing comes from the
// resolver, identity from the declaration; a caller cannot conflate them
// because DialResolved takes them separately.
func (d *Dialer) DialPeer(ctx context.Context, name primitive.Host, port primitive.Port, trust endpoint.Trust) (*VerifiedConn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("transport: peer %s: port %d out of range 1..65535", name, port)
	}
	addrs, err := d.LookupHost(ctx, name.String())
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("transport: no addresses resolved for %s", name)
	}
	dialPort := uint16(port)
	return DialResolved(ctx, netip.AddrPortFrom(addrs[0], dialPort), name, trust)
}

// Probe performs a one-shot DNS-over-TLS roundtrip against the declared
// resolver, used as a pre-flight check at strike run start, and returns
// the ConnectionIdentity observed at the TLS handshake. The probe target
// is an NS query on "." (the root zone), which every standards-compliant
// DoT resolver answers; this avoids encoding any provider-specific sanity
// name.
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
// DialResolved during this same handshake; the returned identity is
// what that verified handshake observed.
//
// Probe placement: see docs/ADR-028-step-container-egress-mediation.md,
// "Operational requirement: a reachable DoT resolver". The probe runs
// at strike run time, after lane.Parse, not in lane.Parse, because
// probe outcome is an environmental property and lane.Parse must
// stay an offline check of input properties.
func (d *Dialer) Probe(ctx context.Context) (ConnectionIdentity, error) {
	var ic identityCapture
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := d.dialResolver(ctx)
			if err != nil {
				return nil, err
			}
			ic.record(conn.Identity())
			return conn.Conn(), nil
		},
	}
	if _, err := r.LookupNS(ctx, "."); err != nil {
		clearMisleadingServerField(err)
		return ConnectionIdentity{}, fmt.Errorf("transport: resolver probe via %s: %w", d.resolver.Address.Authority(), err)
	}
	id, ok := ic.get()
	if !ok {
		return ConnectionIdentity{}, fmt.Errorf("transport: resolver probe via %s: no TLS identity captured", d.resolver.Address.Authority())
	}
	return id, nil
}
