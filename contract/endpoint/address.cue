// Address is the network location of an endpoint strike contacts: a bare host,
// an optional port, and -- for URL-bearing endpoints -- an optional canonical
// path. It is representation-neutral (ADR-048): the convolute wire forms, a
// packed "host:port" authority and an "https://host:port/path" URL, are
// projected in and out by the hand-written Parse/Authority/URL functions in
// internal/endpoint, not encoded in this type.
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
// serializes to at a boundary. Like #Authority it is a specify-register
// constraint (ADR-048): a boundary field carries #URL as its CUE type so the
// https-only wire string validates, and redirects its Go type to Address so
// internal code holds the representation-neutral value. ParseURL and
// Address.URL round-trip the string; the optional port and path are parsed in
// Go, so the constraint pins only the https scheme that makes a plaintext base
// a parse error rather than a runtime rejection.
#URL: =~"^https://"
