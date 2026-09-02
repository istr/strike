package endpoint

import (
	"fmt"
	"net/netip"

	"github.com/istr/strike/internal/primitive"
)

// defaultDoTPort is the DNS-over-TLS port (RFC 7858). A declaration that
// omits the port means this one. The default lives here rather than in a CUE
// default arm for the same reason the address projection does: the wire form
// stays what the operator wrote, and the resolution happens where the value
// is used.
const defaultDoTPort primitive.Port = 853

// DialTarget projects the declaration into the address the dial connects to:
// the declared IP, parsed and checked for canonicality, paired with the
// declared port or 853. It is the only place the IP literal is parsed, so a
// caller cannot reach a routing decision by another route.
//
// The ADN is deliberately absent from the result. Routing and identity are
// two values here (RFC 8310 section 3), and DialResolved takes them
// separately, so nothing packs them back together.
func (d DoT) DialTarget() (netip.AddrPort, error) {
	addr, err := d.IP.Addr()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolver: %w", err)
	}
	port := defaultDoTPort
	if d.Port != nil {
		port = *d.Port
	}
	if port < 1 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf(
			"resolver: port %d out of range 1..65535", port)
	}
	dialPort := uint16(port)
	return netip.AddrPortFrom(addr, dialPort), nil
}
