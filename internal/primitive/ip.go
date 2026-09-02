package primitive

import (
	"fmt"
	"net/netip"
)

// String returns the IP literal as a plain string. It is the single
// sanctioned IP-to-string conversion: call sites use i.String(), never
// string(i), so no type conversion sits in an argument list.
func (i IP) String() string {
	return string(i)
}

// Addr parses the literal into a netip.Addr. It is the binding half of the
// lax-schema/binding-Go split the CUE constraint describes: the schema pins
// the alphabet, this pins validity. Three things are rejected beyond what
// netip.ParseAddr rejects on its own -- a zone id, which names a host-local
// interface and cannot mean anything in an attested lane, and any
// non-canonical spelling, so that the declared literal and the value it
// denotes are one string rather than two.
func (i IP) Addr() (netip.Addr, error) {
	a, err := netip.ParseAddr(string(i))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ip %q: %w", string(i), err)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("ip %q: zone id not permitted", string(i))
	}
	if a.String() != string(i) {
		return netip.Addr{}, fmt.Errorf(
			"ip %q: not canonical, write it as %q", string(i), a.String())
	}
	return a, nil
}

// IPFromAddr renders a parsed address as its canonical IP literal. It is the
// single sanctioned string-to-IP conversion, mirroring DigestFromHex.
func IPFromAddr(a netip.Addr) IP {
	return IP(a.String())
}
