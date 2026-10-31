// Address is the network location of an endpoint strike contacts: a bare host,
// an optional port, and -- for URL-bearing endpoints -- an optional canonical
// path. It is representation-neutral (ADR-048): the convolute wire forms, a
// packed "host:port" authority, an "https://host:port/path" URL, and a
// render-only bracket-delimited "[host]:port" pair, are projected in and out
// by the hand-written functions in internal/endpoint, not encoded in this
// type.
package endpoint

import "github.com/istr/strike/contract/primitive"

#Address: {
	@go(Address)
	host:  primitive.#Host    @go(Host)
	port?: primitive.#Port    @go(Port,optional=nillable)
	path?: primitive.#AbsPath @go(Path,optional=nillable)
}

// Authority is the packed "host[:port]" wire form an Address serializes to at a
// boundary. It is a specify-register constraint (ADR-048), single-sourcing the
// host:port grammar that ParseAuthority and Address.Authority round-trip: a
// boundary field carries #Authority as its CUE type so the wire string
// validates, and redirects its Go type to Address so internal code holds the
// representation-neutral value.
#Authority: =~"^[a-z0-9.-]+(:[0-9]+)?$"

// URL is the "https://host[:port][/path]" wire form a URL-bearing Address
// serializes to at a boundary, and the single URL form strike accepts. It is a
// restricted RFC 3986 URL: the https scheme and a host are mandatory, the host
// carries the #Authority host grammar, a port carries no leading zero, and a
// query or fragment component is forbidden. The restriction keeps it
// compatible with the OpenID Connect issuer identifier, which is compared
// byte-exactly, and with every other URL-bearing use. Like #Authority it is a
// specify-register constraint (ADR-048): a boundary field carries #URL as its
// CUE type so the wire string validates, and redirects its Go type to Address
// so internal code holds the representation-neutral value. ParseURL and
// Address.URL round-trip the string; ParseURL also rejects a query, a
// fragment, and any input that does not round-trip, and range-checks the port.
#URL: =~"^https://[a-z0-9.-]+(:[1-9][0-9]*)?(/[^?#]*)?$"
