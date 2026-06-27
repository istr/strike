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
